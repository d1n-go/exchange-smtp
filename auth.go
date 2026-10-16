package exchangesmtp

import (
	"errors"
	"net/smtp"
)

// loginAuth is analog for plain auth for Exchange server.
// This is smtp.Auth interface implementation.
type loginAuth struct {
	username, password string
	allowInsecure      bool
}

// Start begins an authentication with a server.
// Like smtp.PlainAuth, it refuses to send credentials over an unencrypted
// connection unless the server is localhost or insecure auth is allowed.
func (a *loginAuth) Start(info *smtp.ServerInfo) (string, []byte, error) {
	if info == nil {
		return "", nil, errors.New("smtp: missing server info")
	}
	if !info.TLS && !a.allowInsecure && !isLocalhost(info.Name) {
		return "", nil, errors.New("smtp: refusing LOGIN auth over unencrypted connection (use TLS or allow insecure auth)")
	}
	return "LOGIN", nil, nil
}

// Next continues the authentication.
func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("unknown from server: " + string(fromServer))
		}
	}
	return nil, nil
}

// LoginAuth uses for authorization in Exchange.
// Plain auth for Exchange server doesn't work since 2017.
// Credentials are sent only over TLS (or to localhost).
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username: username, password: password}
}

// InsecureLoginAuth is like LoginAuth but also sends credentials over an
// unencrypted connection. Use it only inside a trusted network, e.g. for an
// old Exchange on port 25 without a certificate.
func InsecureLoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username: username, password: password, allowInsecure: true}
}

func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}
