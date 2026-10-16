// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2026 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package kerberos

import "context"

// Request describes a single GSSAPI context establishment. The driver builds it
// from the server's authentication switch payload and the connection's
// credentials. Implementations must treat it as read-only.
type Request struct {
	// SPN is the service principal name advertised by the MySQL server, for
	// example "MySQL/db.example.com@EXAMPLE.COM". It is never empty.
	SPN string

	// Realm is the user principal realm advertised by the MySQL server. It is
	// empty when the server does not send one, in which case the provider
	// should fall back to its own configuration or krb5.conf.
	Realm string

	// Username is the account name used for the connection, with any "@REALM"
	// suffix removed. It is the MySQL user unless [Config.Username] overrides it.
	Username string

	// Password is the DSN password. It is empty when the DSN has none, in which
	// case an existing credential cache or a keytab must supply the credentials.
	//
	// The password is never sent to the MySQL server. It is only used locally to
	// obtain a ticket-granting ticket from the KDC.
	Password string
}

// Provider creates the GSSAPI initiator used for an authentication exchange.
// The driver calls NewInitiator once per connection attempt, possibly
// concurrently, so implementations must be safe for concurrent use.
//
// [GoKrb5Provider] is the default implementation. Supply a different one
// through [Config.Provider] to integrate with a platform GSSAPI library such as
// Windows SSPI.
type Provider interface {
	// NewInitiator returns an initiator for req. Returning an error aborts
	// authentication. ctx is the connection's context and may be canceled while
	// the call is running.
	NewInitiator(ctx context.Context, req Request) (Initiator, error)
}

// Initiator drives the client side of a GSSAPI context establishment. The
// driver calls the methods sequentially on a single connection and always calls
// Close exactly once when it is finished with the initiator.
type Initiator interface {
	// Init returns the first context token to send to the server. It must
	// return a non-empty token or an error.
	Init(ctx context.Context) ([]byte, error)

	// Step consumes a context token received from the server and returns the
	// next token to send. token must not be modified or retained.
	//
	// Returning a non-empty token sends it and waits for the server's reply.
	// Returning an empty token means the initiator has nothing more to send, in
	// which case Complete must report true.
	Step(ctx context.Context, token []byte) ([]byte, error)

	// Complete reports whether the security context is fully established,
	// including mutual authentication of the server when it was requested.
	// Authentication only succeeds if the MySQL server also returns OK.
	Complete() bool

	// Close releases any resources held by the initiator. It must be safe to
	// call more than once.
	Close() error
}
