// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2026 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package kerberos

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jcmturner/gokrb5/v8/config"
)

// buildAuthData encodes a Kerberos authentication switch payload.
func buildAuthData(spn, realm string) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(spn)))
	b = append(b, spn...)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(realm)))
	return append(b, realm...)
}

// fakeInitiator is a scripted Initiator used to drive the plugin state machine.
type fakeInitiator struct {
	initToken []byte
	initErr   error

	// steps are returned in order, one per Step call.
	steps    [][]byte
	stepErr  error
	complete bool

	received  [][]byte
	stepCalls int
	closed    int
}

func (f *fakeInitiator) Init(ctx context.Context) ([]byte, error) {
	return f.initToken, f.initErr
}

func (f *fakeInitiator) Step(ctx context.Context, token []byte) ([]byte, error) {
	f.received = append(f.received, append([]byte(nil), token...))
	if f.stepErr != nil {
		return nil, f.stepErr
	}
	i := f.stepCalls
	f.stepCalls++
	if i < len(f.steps) {
		return f.steps[i], nil
	}
	return nil, nil
}

func (f *fakeInitiator) Complete() bool { return f.complete }

func (f *fakeInitiator) Close() error {
	f.closed++
	return nil
}

// fakeProvider hands out a prepared initiator and records the request.
type fakeProvider struct {
	initiator *fakeInitiator
	err       error
	got       Request
	calls     int
}

func (p *fakeProvider) NewInitiator(ctx context.Context, req Request) (Initiator, error) {
	p.calls++
	p.got = req
	if p.err != nil {
		return nil, p.err
	}
	return p.initiator, nil
}

// newTestPlugin builds a plugin wired to prov without applying gokrb5 defaults.
func newTestPlugin(cfg Config, prov Provider) *plugin {
	cfg.Provider = prov
	return &plugin{cfg: cfg}
}

func TestParseAuthData(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		spn       string
		realm     string
		wantError bool
	}{
		{
			name:  "spn and realm",
			data:  buildAuthData("MySQL/db.example.com@EXAMPLE.COM", "EXAMPLE.COM"),
			spn:   "MySQL/db.example.com@EXAMPLE.COM",
			realm: "EXAMPLE.COM",
		},
		{
			name:  "empty realm",
			data:  buildAuthData("MySQL/db.example.com@EXAMPLE.COM", ""),
			spn:   "MySQL/db.example.com@EXAMPLE.COM",
			realm: "",
		},
		{
			// The driver strips the trailing NUL the auth switch packet adds.
			name:  "realm missing its stripped NUL terminator",
			data:  buildAuthData("MySQL/db@EXAMPLE.COM", "EXAMPLE.COM!")[:2+20+2+11],
			spn:   "MySQL/db@EXAMPLE.COM",
			realm: "EXAMPLE.COM",
		},
		{name: "empty", data: nil, wantError: true},
		{name: "truncated spn length", data: []byte{0x01}, wantError: true},
		{name: "truncated spn", data: []byte{0x10, 0x00, 'a', 'b'}, wantError: true},
		{name: "missing realm length", data: buildAuthData("spn", "")[:5], wantError: true},
		{
			name:      "20 byte native scramble is rejected",
			data:      bytes.Repeat([]byte{0xAB}, 20),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spn, realm, err := parseAuthData(tt.data)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected an error, got spn=%q realm=%q", spn, realm)
				}
				if !errors.Is(err, mysql.ErrMalformPkt) {
					t.Errorf("expected error to wrap ErrMalformPkt, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if spn != tt.spn {
				t.Errorf("spn: got %q, want %q", spn, tt.spn)
			}
			if realm != tt.realm {
				t.Errorf("realm: got %q, want %q", realm, tt.realm)
			}
		})
	}
}

func TestInitAuthBuildsRequest(t *testing.T) {
	init := &fakeInitiator{initToken: []byte("AP-REQ")}
	prov := &fakeProvider{initiator: init}
	p := newTestPlugin(Config{}, prov)

	token, err := p.InitAuth(context.Background(),
		buildAuthData("MySQL/db.example.com@EXAMPLE.COM", "EXAMPLE.COM"),
		&mysql.AuthContext{})
	if err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	if string(token) != "AP-REQ" {
		t.Errorf("token: got %q, want %q", token, "AP-REQ")
	}
	if prov.got.SPN != "MySQL/db.example.com@EXAMPLE.COM" {
		t.Errorf("SPN: got %q", prov.got.SPN)
	}
	if prov.got.Realm != "EXAMPLE.COM" {
		t.Errorf("Realm: got %q", prov.got.Realm)
	}
}

func TestInitAuthUsernameAndRealm(t *testing.T) {
	tests := []struct {
		name      string
		configure string
		realm     string
		wantUser  string
		wantRealm string
	}{
		{name: "server realm", realm: "EXAMPLE.COM", wantRealm: "EXAMPLE.COM"},
		{
			name:      "config username",
			configure: "svc_mysql",
			realm:     "EXAMPLE.COM",
			wantUser:  "svc_mysql",
			wantRealm: "EXAMPLE.COM",
		},
		{
			// A principal-style username carries its own realm, which wins.
			name:      "username realm overrides server realm",
			configure: "svc_mysql@OTHER.COM",
			realm:     "EXAMPLE.COM",
			wantUser:  "svc_mysql",
			wantRealm: "OTHER.COM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := &fakeProvider{initiator: &fakeInitiator{initToken: []byte("t")}}
			p := newTestPlugin(Config{Username: tt.configure}, prov)

			if _, err := p.InitAuth(context.Background(),
				buildAuthData("MySQL/db@EXAMPLE.COM", tt.realm),
				&mysql.AuthContext{}); err != nil {
				t.Fatalf("InitAuth: %v", err)
			}
			if prov.got.Username != tt.wantUser {
				t.Errorf("Username: got %q, want %q", prov.got.Username, tt.wantUser)
			}
			if prov.got.Realm != tt.wantRealm {
				t.Errorf("Realm: got %q, want %q", prov.got.Realm, tt.wantRealm)
			}
		})
	}
}

func TestExchangeCompletes(t *testing.T) {
	init := &fakeInitiator{initToken: []byte("AP-REQ"), complete: true}
	p := newTestPlugin(Config{}, &fakeProvider{initiator: init})

	if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err != nil {
		t.Fatalf("InitAuth: %v", err)
	}

	// The server's AP-REP completes the context; the plugin closes the handshake
	// with an empty packet and then expects OK.
	next, err := p.ContinuationAuth(context.Background(), []byte("AP-REP"), nil, &mysql.AuthContext{})
	if err != nil {
		t.Fatalf("ContinuationAuth: %v", err)
	}
	if next == nil || len(next) != 0 {
		t.Errorf("expected a non-nil empty final token, got %#v", next)
	}
	if len(init.received) != 1 || string(init.received[0]) != "AP-REP" {
		t.Errorf("initiator received %q", init.received)
	}
	if init.closed == 0 {
		t.Error("expected the initiator to be closed")
	}

	// Any further packet means the server is out of step.
	if _, err := p.ContinuationAuth(context.Background(), []byte("x"), nil, &mysql.AuthContext{}); !errors.Is(err, mysql.ErrMalformPkt) {
		t.Errorf("expected ErrMalformPkt after the exchange ended, got %v", err)
	}
}

func TestExchangeSuppressFinalToken(t *testing.T) {
	init := &fakeInitiator{initToken: []byte("AP-REQ"), complete: true}
	p := newTestPlugin(Config{SuppressFinalToken: true}, &fakeProvider{initiator: init})

	if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	next, err := p.ContinuationAuth(context.Background(), []byte("AP-REP"), nil, &mysql.AuthContext{})
	if err != nil {
		t.Fatalf("ContinuationAuth: %v", err)
	}
	if next != nil {
		t.Errorf("expected nil so the driver only reads, got %#v", next)
	}
}

func TestExchangeMultipleRounds(t *testing.T) {
	init := &fakeInitiator{
		initToken: []byte("tok0"),
		steps:     [][]byte{[]byte("tok1"), nil},
		complete:  true,
	}
	p := newTestPlugin(Config{}, &fakeProvider{initiator: init})

	if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	next, err := p.ContinuationAuth(context.Background(), []byte("srv1"), nil, &mysql.AuthContext{})
	if err != nil {
		t.Fatalf("round 1: %v", err)
	}
	if string(next) != "tok1" {
		t.Fatalf("round 1 token: got %q, want %q", next, "tok1")
	}
	next, err = p.ContinuationAuth(context.Background(), []byte("srv2"), nil, &mysql.AuthContext{})
	if err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if next == nil || len(next) != 0 {
		t.Errorf("round 2: expected the empty final token, got %#v", next)
	}
}

func TestExchangeRejectsIncompleteContext(t *testing.T) {
	// The initiator stops producing tokens without establishing the context,
	// which is what happens if a server skips mutual authentication.
	init := &fakeInitiator{initToken: []byte("AP-REQ"), complete: false}
	p := newTestPlugin(Config{}, &fakeProvider{initiator: init})

	if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	if _, err := p.ContinuationAuth(context.Background(), []byte("junk"), nil, &mysql.AuthContext{}); !errors.Is(err, ErrIncompleteContext) {
		t.Fatalf("expected ErrIncompleteContext, got %v", err)
	}
	if init.closed == 0 {
		t.Error("expected the initiator to be closed")
	}
}

func TestExchangeBoundsRounds(t *testing.T) {
	// A server that keeps sending tokens must not loop forever.
	steps := make([][]byte, maxRounds+1)
	for i := range steps {
		steps[i] = []byte("more")
	}
	init := &fakeInitiator{initToken: []byte("AP-REQ"), steps: steps}
	p := newTestPlugin(Config{}, &fakeProvider{initiator: init})

	if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	for i := 0; i < maxRounds; i++ {
		if _, err := p.ContinuationAuth(context.Background(), []byte("srv"), nil, &mysql.AuthContext{}); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	if _, err := p.ContinuationAuth(context.Background(), []byte("srv"), nil, &mysql.AuthContext{}); !errors.Is(err, ErrTooManyRounds) {
		t.Fatalf("expected ErrTooManyRounds, got %v", err)
	}
}

func TestInitiatorErrorsClose(t *testing.T) {
	t.Run("init error", func(t *testing.T) {
		init := &fakeInitiator{initErr: errors.New("no ticket")}
		p := newTestPlugin(Config{}, &fakeProvider{initiator: init})
		if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err == nil {
			t.Fatal("expected an error")
		}
		if init.closed == 0 {
			t.Error("expected the initiator to be closed")
		}
	})

	t.Run("empty initial token", func(t *testing.T) {
		init := &fakeInitiator{}
		p := newTestPlugin(Config{}, &fakeProvider{initiator: init})
		if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err == nil {
			t.Fatal("expected an error")
		}
		if init.closed == 0 {
			t.Error("expected the initiator to be closed")
		}
	})

	t.Run("step error", func(t *testing.T) {
		init := &fakeInitiator{initToken: []byte("AP-REQ"), stepErr: errors.New("bad AP-REP")}
		p := newTestPlugin(Config{}, &fakeProvider{initiator: init})
		if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err != nil {
			t.Fatalf("InitAuth: %v", err)
		}
		if _, err := p.ContinuationAuth(context.Background(), []byte("srv"), nil, &mysql.AuthContext{}); err == nil {
			t.Fatal("expected an error")
		}
		if init.closed == 0 {
			t.Error("expected the initiator to be closed")
		}
	})
}

func TestProviderError(t *testing.T) {
	prov := &fakeProvider{err: errors.New("no krb5.conf")}
	p := newTestPlugin(Config{}, prov)
	if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNilProvider(t *testing.T) {
	p := &plugin{} // Provider deliberately left nil.
	if _, err := p.InitAuth(context.Background(), buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("expected ErrNoProvider, got %v", err)
	}
}

func TestCleartextFallback(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		prov := &fakeProvider{initiator: &fakeInitiator{}}
		p := newTestPlugin(Config{}, prov)
		// No authentication data means the server cannot offer Kerberos.
		if _, err := p.InitAuth(context.Background(), nil, &mysql.AuthContext{}); !errors.Is(err, ErrFallbackDisabled) {
			t.Fatalf("expected ErrFallbackDisabled, got %v", err)
		}
		if prov.calls != 0 {
			t.Error("the provider should not be used when there is no SPN")
		}
	})

	t.Run("refused on an unprotected transport", func(t *testing.T) {
		p := newTestPlugin(Config{AllowCleartextFallback: true}, &fakeProvider{})
		if _, err := p.cleartextFallback(false, "secret"); !errors.Is(err, ErrFallbackInsecure) {
			t.Fatalf("expected ErrFallbackInsecure, got %v", err)
		}
	})

	t.Run("allowed on a protected transport", func(t *testing.T) {
		p := newTestPlugin(Config{AllowCleartextFallback: true}, &fakeProvider{})
		resp, err := p.cleartextFallback(true, "secret")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := append([]byte("secret"), 0); !bytes.Equal(resp, want) {
			t.Errorf("response: got %q, want %q", resp, want)
		}
	})
}

func TestContinuationBeforeInit(t *testing.T) {
	p := newTestPlugin(Config{}, &fakeProvider{})
	if _, err := p.ContinuationAuth(context.Background(), []byte("srv"), nil, &mysql.AuthContext{}); !errors.Is(err, mysql.ErrMalformPkt) {
		t.Fatalf("expected ErrMalformPkt, got %v", err)
	}
}

func TestCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prov := &fakeProvider{initiator: &fakeInitiator{initToken: []byte("t")}}
	p := newTestPlugin(Config{}, prov)
	if _, err := p.InitAuth(ctx, buildAuthData("MySQL/db", "R"), &mysql.AuthContext{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if prov.calls != 0 {
		t.Error("the provider should not run with a canceled context")
	}
}

func TestConfigWithDefaults(t *testing.T) {
	cfg := Config{}
	got := cfg.withDefaults()
	if _, ok := got.Provider.(*GoKrb5Provider); !ok {
		t.Errorf("expected a default *GoKrb5Provider, got %T", got.Provider)
	}
	if cfg.Provider != nil {
		t.Error("withDefaults must not modify the caller's Config")
	}

	prov := &fakeProvider{}
	if got := (Config{Provider: prov}).withDefaults(); got.Provider != Provider(prov) {
		t.Error("withDefaults must keep an explicit Provider")
	}
}

func TestSplitSPN(t *testing.T) {
	tests := []struct {
		name      string
		spn       string
		principal string
		realm     string
	}{
		{
			// gokrb5 splits on "/" only, so leaving "@REALM" attached makes the
			// KDC answer KDC_ERR_S_PRINCIPAL_UNKNOWN.
			name:      "service host and realm",
			spn:       "mysql/wh-166f758b38.svr.us.jpmchase.net@EXCHAD.JPMCHASE.NET",
			principal: "mysql/wh-166f758b38.svr.us.jpmchase.net",
			realm:     "EXCHAD.JPMCHASE.NET",
		},
		{
			name:      "no realm",
			spn:       "mysql/db.example.com",
			principal: "mysql/db.example.com",
			realm:     "",
		},
		{
			name:      "realm separator is the last at sign",
			spn:       "mysql/db@weird.example.com@EXAMPLE.COM",
			principal: "mysql/db@weird.example.com",
			realm:     "EXAMPLE.COM",
		},
		{name: "empty", spn: "", principal: "", realm: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal, realm := splitSPN(tt.spn)
			if principal != tt.principal {
				t.Errorf("principal: got %q, want %q", principal, tt.principal)
			}
			if realm != tt.realm {
				t.Errorf("realm: got %q, want %q", realm, tt.realm)
			}
		})
	}
}

func TestSPNHost(t *testing.T) {
	tests := []struct {
		principal string
		want      string
	}{
		{"mysql/db.example.com", "db.example.com"},
		{"mysql/db.example.com/extra", "db.example.com"},
		{"mysql", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := spnHost(tt.principal); got != tt.want {
			t.Errorf("spnHost(%q): got %q, want %q", tt.principal, got, tt.want)
		}
	}
}

func TestWithSPNRealm(t *testing.T) {
	base := config.New()
	base.DomainRealm[".example.com"] = "EXAMPLE.COM"

	t.Run("adds an exact host mapping", func(t *testing.T) {
		got := withSPNRealm(base, "db.other.net", "OTHER.NET")
		if got == base {
			t.Fatal("expected a copy, not the shared configuration")
		}
		if r := got.ResolveRealm("db.other.net"); r != "OTHER.NET" {
			t.Errorf("resolved realm: got %q, want %q", r, "OTHER.NET")
		}
		// The shared configuration must be untouched, since a provider serves
		// connections concurrently.
		if _, ok := base.DomainRealm["db.other.net"]; ok {
			t.Error("the original configuration was mutated")
		}
		if r := got.ResolveRealm("host.example.com"); r != "EXAMPLE.COM" {
			t.Errorf("existing mapping lost: got %q", r)
		}
	})

	t.Run("no change when already correct", func(t *testing.T) {
		if got := withSPNRealm(base, "host.example.com", "EXAMPLE.COM"); got != base {
			t.Error("expected the shared configuration to be reused")
		}
	})

	t.Run("no change without a host or realm", func(t *testing.T) {
		if got := withSPNRealm(base, "", "EXAMPLE.COM"); got != base {
			t.Error("expected no copy without a host")
		}
		if got := withSPNRealm(base, "db.other.net", ""); got != base {
			t.Error("expected no copy without a realm")
		}
	})
}

func TestSPNOverride(t *testing.T) {
	prov := &fakeProvider{initiator: &fakeInitiator{initToken: []byte("t")}}
	p := newTestPlugin(Config{SPN: "mysql/lb.example.com@EXAMPLE.COM"}, prov)

	if _, err := p.InitAuth(context.Background(),
		buildAuthData("mysql/backend-node-7.example.com@EXAMPLE.COM", "EXAMPLE.COM"),
		&mysql.AuthContext{}); err != nil {
		t.Fatalf("InitAuth: %v", err)
	}
	if prov.got.SPN != "mysql/lb.example.com@EXAMPLE.COM" {
		t.Errorf("SPN: got %q, want the configured override", prov.got.SPN)
	}
}

func TestGoKrb5ProviderCCachePath(t *testing.T) {
	tests := []struct {
		name      string
		configure string
		env       string
		want      string
		wantError bool
	}{
		{name: "explicit path", configure: "/tmp/krb5cc_1000", want: "/tmp/krb5cc_1000"},
		{name: "FILE prefix stripped", configure: "FILE:/tmp/krb5cc_1000", want: "/tmp/krb5cc_1000"},
		{name: "from environment", env: "/tmp/env_cc", want: "/tmp/env_cc"},
		{name: "windows path kept", configure: `C:\Users\me\krb5cc`, want: `C:\Users\me\krb5cc`},
		{name: "unsupported cache type", configure: "KEYRING:persistent:1000", wantError: true},
		{name: "unsupported windows LSA cache", configure: "MSLSA:", wantError: true},
		{name: "nothing configured", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KRB5CCNAME", tt.env)
			p := &GoKrb5Provider{CCachePath: tt.configure}
			got, err := p.ccachePath()
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRegisteredWithDriver(t *testing.T) {
	// The package init registers the plugin, so the driver must know the name.
	// Registering again with an explicit config must replace it cleanly.
	Register(Config{Username: "svc"})

	cfg := mysql.NewConfig()
	cfg.User = "u"
	cfg.Passwd = "p"
	cfg.Net = "tcp"
	cfg.Addr = "127.0.0.1:3306"
	if _, err := mysql.NewConnector(cfg); err != nil {
		t.Fatalf("NewConnector: %v", err)
	}
}
