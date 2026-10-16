// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2026 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package kerberos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// GoKrb5Provider is the default [Provider]. It is a pure Go GSSAPI initiator
// built on github.com/jcmturner/gokrb5, so it needs no system Kerberos library.
//
// The zero value resolves everything from the environment and is ready to use.
type GoKrb5Provider struct {
	// ConfigPath is the path to krb5.conf. When empty the provider uses
	// $KRB5_CONFIG and then the platform's default location.
	ConfigPath string

	// CCachePath is the path to a credential cache file. When empty the
	// provider uses $KRB5CCNAME. Only file caches are supported; an optional
	// "FILE:" prefix is accepted.
	CCachePath string

	// KeytabPath is the path to a keytab. When set it takes precedence over the
	// DSN password and the credential cache, and the provider logs in to the
	// KDC itself.
	KeytabPath string

	// Realm is the default realm, used only when neither the server nor the
	// username supplies one and krb5.conf has no default_realm.
	Realm string

	// DisablePAFXFAST turns off PA-FX-FAST. Some KDCs, notably Active
	// Directory, require this.
	DisablePAFXFAST bool

	// Settings are additional gokrb5 client settings applied to every client.
	Settings []func(*client.Settings)

	once sync.Once
	conf *config.Config
	err  error
}

// Compile-time assertion that GoKrb5Provider implements Provider.
var _ Provider = (*GoKrb5Provider)(nil)

// NewInitiator implements [Provider]. It resolves credentials in this order:
// keytab, DSN password, credential cache.
func (p *GoKrb5Provider) NewInitiator(ctx context.Context, req Request) (Initiator, error) {
	conf, err := p.loadConfig()
	if err != nil {
		return nil, err
	}

	// gokrb5 documents the SPN as "<SERVICE>/<FQDN>" and splits it on "/"
	// only, so a trailing "@REALM" would become part of the host component.
	principal, spnRealm := splitSPN(req.SPN)
	if principal == "" {
		return nil, fmt.Errorf("invalid service principal name %q", req.SPN)
	}
	// The server names the realm its SPN lives in, which is more authoritative
	// than guessing from krb5.conf, and is what makes a cross-realm service
	// resolvable at all.
	conf = withSPNRealm(conf, spnHost(principal), spnRealm)

	realm := req.Realm
	if realm == "" {
		realm = p.Realm
	}
	if realm == "" {
		realm = conf.LibDefaults.DefaultRealm
	}

	cl, err := p.newClient(ctx, conf, realm, req)
	if err != nil {
		return nil, err
	}
	return &gokrb5Initiator{client: cl, spn: principal, fullSPN: req.SPN}, nil
}

// splitSPN separates a service principal name into its principal and realm
// parts, so that "mysql/db.example.com@EXAMPLE.COM" yields
// "mysql/db.example.com" and "EXAMPLE.COM". The realm is empty when the name
// carries none.
//
// The realm separator is the last "@": realms never contain one, while a
// principal component may.
func splitSPN(spn string) (principal, realm string) {
	if i := strings.LastIndex(spn, "@"); i >= 0 {
		return spn[:i], spn[i+1:]
	}
	return spn, ""
}

// spnHost returns the host component of a "service/host" principal, or an
// empty string when there is none.
func spnHost(principal string) string {
	parts := strings.Split(principal, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// withSPNRealm returns a configuration that resolves host to realm. It copies
// the configuration rather than mutating the shared one, because a single
// provider serves connections concurrently.
func withSPNRealm(conf *config.Config, host, realm string) *config.Config {
	if host == "" || realm == "" || conf.ResolveRealm(host) == realm {
		return conf
	}
	updated := *conf
	mapping := make(config.DomainRealm, len(conf.DomainRealm)+1)
	for k, v := range conf.DomainRealm {
		mapping[k] = v
	}
	mapping[host] = realm
	updated.DomainRealm = mapping
	return &updated
}

// newClient builds and, where necessary, logs in a gokrb5 client.
func (p *GoKrb5Provider) newClient(ctx context.Context, conf *config.Config, realm string, req Request) (*client.Client, error) {
	settings := p.clientSettings()

	switch {
	case p.KeytabPath != "":
		if req.Username == "" {
			return nil, errors.New("keytab authentication requires a username; set Config.Username or the DSN user")
		}
		if realm == "" {
			return nil, errors.New("keytab authentication requires a realm; set GoKrb5Provider.Realm or default_realm in krb5.conf")
		}
		kt, err := keytab.Load(p.KeytabPath)
		if err != nil {
			return nil, fmt.Errorf("loading keytab %q: %w", p.KeytabPath, err)
		}
		cl := client.NewWithKeytab(req.Username, realm, kt, conf, settings...)
		if err := login(ctx, cl); err != nil {
			cl.Destroy()
			return nil, fmt.Errorf("keytab login for %s@%s: %w", req.Username, realm, err)
		}
		return cl, nil

	case req.Password != "":
		if req.Username == "" {
			return nil, errors.New("password authentication requires a username; set Config.Username or the DSN user")
		}
		if realm == "" {
			return nil, errors.New("password authentication requires a realm; the server sent none and krb5.conf has no default_realm")
		}
		cl := client.NewWithPassword(req.Username, realm, req.Password, conf, settings...)
		if err := login(ctx, cl); err != nil {
			cl.Destroy()
			// The password must not reach the error string, which may be logged.
			return nil, fmt.Errorf("password login for %s@%s: %w", req.Username, realm, err)
		}
		return cl, nil

	default:
		path, err := p.ccachePath()
		if err != nil {
			return nil, err
		}
		ccache, err := credentials.LoadCCache(path)
		if err != nil {
			return nil, fmt.Errorf("loading credential cache %q: %w", path, err)
		}
		cl, err := client.NewFromCCache(ccache, conf, settings...)
		if err != nil {
			return nil, fmt.Errorf("using credential cache %q: %w", path, err)
		}
		return cl, nil
	}
}

// clientSettings returns a fresh slice so the caller cannot mutate p.Settings.
func (p *GoKrb5Provider) clientSettings() []func(*client.Settings) {
	settings := make([]func(*client.Settings), 0, len(p.Settings)+1)
	settings = append(settings, p.Settings...)
	if p.DisablePAFXFAST {
		settings = append(settings, client.DisablePAFXFAST(true))
	}
	return settings
}

// loadConfig parses krb5.conf once and caches the result.
func (p *GoKrb5Provider) loadConfig() (*config.Config, error) {
	p.once.Do(func() {
		path := p.ConfigPath
		if path == "" {
			path = os.Getenv("KRB5_CONFIG")
		}
		if path == "" {
			for _, candidate := range defaultConfigPaths() {
				if _, err := os.Stat(candidate); err == nil {
					path = candidate
					break
				}
			}
		}
		if path == "" {
			p.err = errors.New("no krb5.conf found; set GoKrb5Provider.ConfigPath or $KRB5_CONFIG")
			return
		}
		conf, err := config.Load(path)
		if err != nil {
			p.err = fmt.Errorf("loading krb5 config %q: %w", path, err)
			return
		}
		p.conf = conf
	})
	return p.conf, p.err
}

// defaultConfigPaths returns the usual krb5.conf locations for the platform.
func defaultConfigPaths() []string {
	if runtime.GOOS == "windows" {
		var paths []string
		if dir := os.Getenv("ProgramData"); dir != "" {
			paths = append(paths, filepath.Join(dir, "MIT", "Kerberos5", "krb5.ini"))
		}
		if dir := os.Getenv("SystemRoot"); dir != "" {
			paths = append(paths, filepath.Join(dir, "krb5.ini"))
		}
		return paths
	}
	return []string{"/etc/krb5.conf"}
}

// ccachePath resolves the credential cache, rejecting cache types this pure Go
// implementation cannot read rather than failing obscurely later.
func (p *GoKrb5Provider) ccachePath() (string, error) {
	path := p.CCachePath
	if path == "" {
		path = os.Getenv("KRB5CCNAME")
	}
	if path == "" {
		return "", errors.New("no credentials available: set GoKrb5Provider.CCachePath or $KRB5CCNAME, configure a keytab, or supply a DSN password")
	}
	kind, rest, found := strings.Cut(path, ":")
	if !found {
		return path, nil
	}
	switch strings.ToUpper(kind) {
	case "FILE":
		return rest, nil
	case "DIR", "API", "KEYRING", "KCM", "MSLSA", "MEMORY":
		return "", fmt.Errorf("credential cache type %q is not supported by GoKrb5Provider; use a FILE cache, a keytab, a DSN password, or a custom Provider", kind)
	default:
		// A bare Windows path such as C:\krb5cc also matches the Cut above.
		return path, nil
	}
}

// login performs the blocking AS exchange while honouring ctx.
func login(ctx context.Context, cl *client.Client) error {
	return runContext(ctx, cl.Login)
}

// runContext runs a blocking gokrb5 call and returns early if ctx is done. The
// goroutine is not cancellable, so it is left to finish on its own; it is bound
// by the KDC timeouts in krb5.conf.
func runContext(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// gokrb5Initiator performs a GSSAPI krb5 AP-REQ/AP-REP exchange.
type gokrb5Initiator struct {
	client *client.Client
	// spn is the "<SERVICE>/<FQDN>" form gokrb5 expects.
	spn string
	// fullSPN is the name the server advertised, used in error messages so
	// they can be matched against the server's configuration.
	fullSPN string

	sessionKey types.EncryptionKey
	ctime      time.Time
	cusec      int
	haveAuth   bool

	sent     bool
	complete bool
}

// Compile-time assertion that gokrb5Initiator implements Initiator.
var _ Initiator = (*gokrb5Initiator)(nil)

// Init obtains a service ticket and returns the GSSAPI AP-REQ token. Mutual
// authentication is requested so the server must prove its identity.
func (i *gokrb5Initiator) Init(ctx context.Context) ([]byte, error) {
	if i.sent {
		return nil, errors.New("initial token already produced")
	}

	var (
		ticket     messages.Ticket
		sessionKey types.EncryptionKey
	)
	err := runContext(ctx, func() (err error) {
		ticket, sessionKey, err = i.client.GetServiceTicket(i.spn)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("obtaining service ticket for %q: %w", i.fullSPN, err)
	}
	i.sessionKey = sessionKey

	token, err := spnego.NewKRB5TokenAPREQ(i.client, ticket, sessionKey,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual},
		[]int{flags.APOptionMutualRequired},
	)
	if err != nil {
		return nil, fmt.Errorf("building AP-REQ for %q: %w", i.fullSPN, err)
	}

	// Keep the authenticator timestamp so the AP-REP can be matched to this
	// request. The authenticator is only available in encrypted form, and we
	// hold the session key that produced it.
	if err := token.APReq.DecryptAuthenticator(sessionKey); err == nil {
		i.ctime = token.APReq.Authenticator.CTime
		i.cusec = token.APReq.Authenticator.Cusec
		i.haveAuth = true
	}

	b, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling AP-REQ for %q: %w", i.fullSPN, err)
	}
	i.sent = true
	return b, nil
}

// Step verifies the server's AP-REP, completing mutual authentication. The
// krb5 mechanism needs no further client token, so it returns nil.
func (i *gokrb5Initiator) Step(ctx context.Context, token []byte) ([]byte, error) {
	if !i.sent {
		return nil, errors.New("received a server token before sending the AP-REQ")
	}
	if i.complete {
		return nil, errors.New("received a server token after the security context was established")
	}
	if len(token) == 0 {
		return nil, errors.New("server sent an empty GSSAPI token")
	}

	var krbToken spnego.KRB5Token
	if err := krbToken.Unmarshal(token); err != nil {
		return nil, fmt.Errorf("parsing the server's GSSAPI token: %w", err)
	}
	switch {
	case krbToken.IsKRBError():
		return nil, fmt.Errorf("server returned a Kerberos error: %s", krbToken.KRBError.Error())
	case !krbToken.IsAPRep():
		return nil, errors.New("server did not return an AP-REP, so mutual authentication failed")
	}

	// Only a principal holding the service key could decrypt the ticket and
	// recover this session key, so a successful decryption authenticates the
	// server.
	b, err := crypto.DecryptEncPart(krbToken.APRep.EncPart, i.sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, fmt.Errorf("mutual authentication failed: decrypting AP-REP: %w", err)
	}
	var encPart messages.EncAPRepPart
	if err := encPart.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("mutual authentication failed: parsing AP-REP: %w", err)
	}
	// RFC 4120 section 3.2.5: the AP-REP must echo the authenticator's
	// timestamp, which binds it to this request and rejects replays.
	if i.haveAuth && (!encPart.CTime.Equal(i.ctime) || encPart.Cusec != i.cusec) {
		return nil, errors.New("mutual authentication failed: AP-REP does not match the AP-REQ authenticator")
	}

	i.complete = true
	return nil, nil
}

// Complete implements [Initiator].
func (i *gokrb5Initiator) Complete() bool { return i.complete }

// Close implements [Initiator].
func (i *gokrb5Initiator) Close() error {
	if i.client != nil {
		i.client.Destroy()
		i.client = nil
	}
	i.sessionKey = types.EncryptionKey{}
	return nil
}
