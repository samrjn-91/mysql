// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2026 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

// Package kerberos adds Kerberos (GSSAPI) authentication to the MySQL driver by
// implementing the server's authentication_kerberos_client plugin.
//
// Import it for its side effects to register the plugin with the environment's
// default Kerberos configuration:
//
//	import _ "github.com/go-sql-driver/mysql/kerberos"
//
// This also registers the mysql database/sql driver. No DSN change is required:
// the server requests Kerberos with an authentication switch when the account
// uses it, and the driver then runs this plugin.
//
// To control where credentials come from, register explicitly instead:
//
//	kerberos.Register(kerberos.Config{
//		Provider: &kerberos.GoKrb5Provider{
//			ConfigPath: "/etc/krb5.conf",
//			KeytabPath: "/etc/mysql.keytab",
//		},
//	})
//
// Credentials are resolved in this order by the default provider: a keytab when
// one is configured, otherwise the DSN password, otherwise an existing
// credential cache. A DSN password is used only to obtain a ticket-granting
// ticket from the KDC; it is never sent to the MySQL server.
//
// The plugin requests mutual authentication and fails the connection unless the
// server proves its identity with a valid AP-REP, so Kerberos authenticates the
// server as well as the client.
//
// # Platform notes
//
// [GoKrb5Provider] is a pure Go implementation and reads MIT-style file
// credential caches. It cannot read the Windows LSA cache, the DIR:, KEYRING:
// or API: cache types, or use the Windows credential store. On Windows, supply
// a keytab or a password, point KRB5CCNAME at a file cache, or plug in an SSPI
// based [Provider].
//
// MariaDB's auth_gssapi_client plugin uses a different wire format and is not
// handled by this package.
package kerberos

import (
	"github.com/go-sql-driver/mysql"
)

// Config configures the Kerberos authentication plugin. The zero value is
// usable and resolves everything from the environment.
type Config struct {
	// Provider supplies the GSSAPI implementation. A nil Provider selects a
	// default [GoKrb5Provider], which reads krb5.conf and the credential cache
	// from the usual locations and environment variables.
	Provider Provider

	// Username overrides the Kerberos principal name. By default the plugin
	// uses the MySQL user from the DSN. Set this when the MySQL account name
	// differs from the Kerberos principal. A trailing "@REALM" is honoured and
	// takes precedence over the realm advertised by the server.
	Username string

	// SPN overrides the service principal name advertised by the server, in
	// "service/host@REALM" form, for example
	// "mysql/db.example.com@EXAMPLE.COM". The realm may be omitted.
	//
	// Set this when the server advertises a name that is not registered with
	// the KDC, which a KDC_ERR_S_PRINCIPAL_UNKNOWN response reports. That
	// happens most often behind a load balancer or proxy, where the server
	// announces its own backend hostname while the SPN is registered against
	// the name clients connect to.
	SPN string

	// AllowCleartextFallback permits sending the DSN password as cleartext when
	// the server starts Kerberos authentication but offers no service principal
	// name, which is how the reference connectors behave.
	//
	// This is a downgrade, so it is disabled by default. When enabled, the
	// plugin still refuses to send the password unless the connection uses
	// driver-managed TLS or a unix socket.
	AllowCleartextFallback bool

	// SendFinalEmptyToken makes the plugin send an empty packet once the
	// security context is established, before reading the server's OK.
	//
	// MySQL's server plugin writes OK without reading again, so the default
	// sends nothing. An extra packet there desynchronises the packet sequence
	// and fails the connection with "commands out of sync". Enable this only
	// for a server that expects the additional exchange.
	SendFinalEmptyToken bool
}

// withDefaults returns a copy of cfg with defaults filled in, leaving the
// caller's value untouched.
func (c Config) withDefaults() Config {
	if c.Provider == nil {
		c.Provider = &GoKrb5Provider{}
	}
	return c
}

// Register registers the Kerberos authentication plugin with the driver using
// cfg, replacing any previous registration. It is safe to call concurrently
// with other registrations, but call it before opening connections so every
// connection sees the same configuration.
func Register(cfg Config) {
	cfg = cfg.withDefaults()
	mysql.RegisterAuthPlugin(PluginName, func() mysql.AuthPlugin {
		// Each exchange gets its own plugin instance, as the driver requires.
		return &plugin{cfg: cfg}
	})
}

func init() {
	// Registering with defaults makes a blank import sufficient. Callers that
	// need explicit settings call Register, which replaces this registration.
	Register(Config{})
}
