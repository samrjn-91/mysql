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
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// PluginName is the MySQL server's name for the Kerberos authentication plugin.
// The server requests it with an authentication switch; it is never the plugin
// named in the initial handshake greeting.
const PluginName = "authentication_kerberos_client"

// maxRounds bounds the GSSAPI token exchange. The driver's continuation loop is
// unbounded, so the plugin must stop a server that never finishes the exchange.
// Kerberos normally needs a single round trip.
const maxRounds = 16

// Errors returned by the plugin.
var (
	// ErrNoSPN is returned when the server starts Kerberos authentication
	// without naming a service principal, which means it cannot perform a
	// GSSAPI exchange.
	ErrNoSPN = errors.New("mysql: kerberos: server did not provide a service principal name")

	// ErrNoProvider is returned when Config.Provider is nil and no default is
	// available.
	ErrNoProvider = errors.New("mysql: kerberos: no GSSAPI provider configured")

	// ErrTooManyRounds is returned when the server exceeds the GSSAPI token
	// exchange limit.
	ErrTooManyRounds = fmt.Errorf("mysql: kerberos: maximum of %d GSSAPI token exchanges reached", maxRounds)

	// ErrFallbackDisabled is returned when the server offers no SPN and the
	// cleartext password fallback has not been enabled.
	ErrFallbackDisabled = errors.New("mysql: kerberos: server offered no SPN and cleartext fallback is disabled; set Config.AllowCleartextFallback to allow it")

	// ErrFallbackInsecure is returned when the cleartext password fallback is
	// enabled but the transport is neither TLS nor a unix socket.
	ErrFallbackInsecure = errors.New("mysql: kerberos: cleartext fallback requires TLS or a unix socket")

	// ErrIncompleteContext is returned when the initiator stops producing
	// tokens before the security context is established. Most importantly this
	// catches a server that skips mutual authentication.
	ErrIncompleteContext = errors.New("mysql: kerberos: server ended the exchange before the security context was established")
)

// plugin implements mysql.AuthPlugin for authentication_kerberos_client.
//
// The exchange is:
//
//  1. The server sends an authentication switch whose payload carries the
//     service principal name and the user principal realm.
//  2. The client obtains a service ticket and replies with a GSSAPI AP-REQ.
//  3. The server replies with an AP-REP, which the client verifies to
//     authenticate the server.
//  4. The server sends OK.
type plugin struct {
	cfg Config

	initiator Initiator
	rounds    int
	finished  bool // no further client tokens may be sent
}

// Compile-time assertion that plugin implements mysql.AuthPlugin.
var _ mysql.AuthPlugin = (*plugin)(nil)

// New returns a Kerberos authentication plugin using cfg. Most callers should
// use [Register] instead, which wires the plugin into the driver.
func New(cfg Config) mysql.AuthPlugin {
	return &plugin{cfg: cfg.withDefaults()}
}

// InitAuth parses the server's SPN and realm and returns the initial GSSAPI
// token. The password, when present, is used only to obtain a ticket from the
// KDC and is never sent to the MySQL server.
func (p *plugin) InitAuth(ctx context.Context, authData []byte, auth *mysql.AuthContext) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// A server that cannot offer Kerberos sends no authentication data. This is
	// the only case where the reference client falls back to the password, and
	// the fallback is a downgrade, so it stays opt-in.
	if len(authData) == 0 {
		p.finished = true
		return p.cleartextFallback(auth.TLS() || auth.UnixSocket(), auth.Password())
	}

	spn, realm, err := parseAuthData(authData)
	if err != nil {
		return nil, err
	}
	if p.cfg.SPN != "" {
		// The configured name wins, because a server behind a load balancer
		// may advertise a backend hostname that the KDC does not know.
		spn = p.cfg.SPN
	}
	if spn == "" {
		return nil, ErrNoSPN
	}

	username := p.cfg.Username
	if username == "" {
		username = auth.User()
	}
	// A principal-style username carries its own realm, which wins over the
	// realm advertised by the server.
	if name, userRealm, found := strings.Cut(username, "@"); found {
		username = name
		if userRealm != "" {
			realm = userRealm
		}
	}

	if p.cfg.Provider == nil {
		return nil, ErrNoProvider
	}

	initiator, err := p.cfg.Provider.NewInitiator(ctx, Request{
		SPN:      spn,
		Realm:    realm,
		Username: username,
		Password: auth.Password(),
	})
	if err != nil {
		return nil, fmt.Errorf("mysql: kerberos: creating GSSAPI initiator: %w", err)
	}
	if initiator == nil {
		return nil, ErrNoProvider
	}
	p.initiator = initiator

	token, err := initiator.Init(ctx)
	if err != nil {
		p.close()
		return nil, fmt.Errorf("mysql: kerberos: %w", err)
	}
	if len(token) == 0 {
		p.close()
		return nil, errors.New("mysql: kerberos: initiator produced an empty initial token")
	}
	return token, nil
}

// ContinuationAuth feeds each server token to the initiator until the security
// context is established. The driver has already handled OK, ERR and
// authentication switch packets and stripped the AuthMoreData prefix.
func (p *plugin) ContinuationAuth(ctx context.Context, packet, authData []byte, auth *mysql.AuthContext) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Nothing more is expected once the exchange ended, so an additional packet
	// means the server is out of step.
	if p.initiator == nil || p.finished {
		return nil, mysql.ErrMalformPkt
	}

	p.rounds++
	if p.rounds > maxRounds {
		p.close()
		return nil, ErrTooManyRounds
	}

	next, err := p.initiator.Step(ctx, packet)
	if err != nil {
		p.close()
		return nil, fmt.Errorf("mysql: kerberos: %w", err)
	}
	if len(next) > 0 {
		// More tokens to exchange before the context is established.
		return next, nil
	}

	// The initiator is out of tokens, so the context must be established.
	// Otherwise the server stopped early, for example by skipping the AP-REP
	// that proves its identity.
	if !p.initiator.Complete() {
		p.close()
		return nil, ErrIncompleteContext
	}
	p.finished = true
	p.close()

	if p.cfg.SuppressFinalToken {
		// Read the server's OK without sending anything further.
		return nil, nil
	}
	// Send an empty packet to close the handshake, matching the reference
	// connectors, then read the server's OK.
	return []byte{}, nil
}

// cleartextFallback reproduces the reference client's behaviour when the server
// cannot offer Kerberos. It sends the password as a NUL-terminated string, so
// it is only allowed over a transport the driver knows to be protected.
func (p *plugin) cleartextFallback(secureTransport bool, password string) ([]byte, error) {
	if !p.cfg.AllowCleartextFallback {
		return nil, ErrFallbackDisabled
	}
	if !secureTransport {
		return nil, ErrFallbackInsecure
	}
	return append([]byte(password), 0), nil
}

// close releases the initiator. It is safe to call more than once.
func (p *plugin) close() {
	if p.initiator != nil {
		// Nothing can act on a cleanup failure at this point, and the
		// authentication result is what matters to the caller.
		_ = p.initiator.Close()
		p.initiator = nil
	}
}

// parseAuthData reads the Kerberos authentication switch payload:
//
//	SPN length        2 bytes, little endian
//	SPN               N bytes
//	UPN realm length  2 bytes, little endian
//	UPN realm         N bytes
func parseAuthData(data []byte) (spn, realm string, err error) {
	spn, rest, err := readUint16Prefixed(data, "SPN")
	if err != nil {
		return "", "", err
	}
	realm, _, err = readUint16Prefixed(rest, "UPN realm")
	if err != nil {
		return "", "", err
	}
	return spn, realm, nil
}

// readUint16Prefixed reads a little-endian length-prefixed string from b and
// returns it with the remaining bytes.
func readUint16Prefixed(b []byte, what string) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, fmt.Errorf("%w: kerberos %s length is truncated", mysql.ErrMalformPkt, what)
	}
	n := int(binary.LittleEndian.Uint16(b))
	b = b[2:]
	if n > len(b) {
		// The driver strips the single NUL terminator that the authentication
		// switch packet appends, so tolerate exactly that one missing byte.
		if n-len(b) != 1 {
			return "", nil, fmt.Errorf("%w: kerberos %s is truncated: want %d bytes, have %d", mysql.ErrMalformPkt, what, n, len(b))
		}
		n = len(b)
	}
	return string(b[:n]), b[n:], nil
}
