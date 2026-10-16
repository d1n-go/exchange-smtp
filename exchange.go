package exchangesmtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"time"
)

// DefaultTimeout limits the whole SMTP session (dial, handshake, auth and data
// transfer) unless overridden with WithTimeout.
const DefaultTimeout = time.Minute

// MailSender sends emails through an Exchange SMTP server using LOGIN auth.
type MailSender struct {
	auth   smtp.Auth
	server string

	tlsConfig         *tls.Config
	helloName         string
	timeout           time.Duration
	implicitTLS       bool
	allowInsecureAuth bool
}

// Option configures a MailSender.
type Option func(*MailSender)

// WithTLSConfig sets the TLS configuration used for STARTTLS or implicit TLS.
// If ServerName is empty, it is filled from the server address.
// Use it to trust an internal CA (RootCAs) or to allow TLS 1.0/1.1 (MinVersion)
// for old Exchange servers.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(ms *MailSender) {
		ms.tlsConfig = cfg.Clone()
	}
}

// WithInsecureSkipVerify disables verification of the server certificate.
// Typical for old on-premises Exchange with a self-signed certificate.
func WithInsecureSkipVerify() Option {
	return func(ms *MailSender) {
		if ms.tlsConfig == nil {
			ms.tlsConfig = &tls.Config{}
		}
		ms.tlsConfig.InsecureSkipVerify = true
	}
}

// WithHelloName sets the name sent in EHLO/HELO instead of "localhost".
// Some Exchange receive connectors reject "localhost".
func WithHelloName(name string) Option {
	return func(ms *MailSender) {
		ms.helloName = name
	}
}

// WithTimeout limits the whole SMTP session. Zero disables the limit.
func WithTimeout(d time.Duration) Option {
	return func(ms *MailSender) {
		ms.timeout = d
	}
}

// WithImplicitTLS connects with TLS from the start (SMTPS, usually port 465)
// instead of upgrading the connection with STARTTLS.
func WithImplicitTLS() Option {
	return func(ms *MailSender) {
		ms.implicitTLS = true
	}
}

// WithAllowInsecureAuth allows sending credentials when the server offers no
// TLS (no STARTTLS and no implicit TLS). Use it only inside a trusted network.
func WithAllowInsecureAuth() Option {
	return func(ms *MailSender) {
		ms.allowInsecureAuth = true
	}
}

// NewMailSender is constructor for MailSender.
// server is "host:port", e.g. "mail.company.local:587".
func NewMailSender(username, password, server string, opts ...Option) *MailSender {
	ms := &MailSender{
		server:  server,
		timeout: DefaultTimeout,
	}
	for _, opt := range opts {
		opt(ms)
	}
	if ms.allowInsecureAuth {
		ms.auth = InsecureLoginAuth(username, password)
	} else {
		ms.auth = LoginAuth(username, password)
	}
	return ms
}

// Send sends the email to all To, Cc and Bcc recipients.
func (ms *MailSender) Send(mail Mail) error {
	return ms.SendContext(context.Background(), mail)
}

// SendContext is like Send but aborts the SMTP session when ctx is done.
func (ms *MailSender) SendContext(ctx context.Context, mail Mail) error {
	b, err := mail.ToBytes()
	if err != nil {
		return err
	}

	if ms.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ms.timeout)
		defer cancel()
	}

	err = ms.send(ctx, bareAddress(mail.From), mail.AllRecipients(), b)
	if err != nil {
		// report timeouts and cancellation as context errors
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("%w: %v", ctxErr, err)
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return fmt.Errorf("%w: %v", context.DeadlineExceeded, err)
		}
	}
	return err
}

func (ms *MailSender) send(ctx context.Context, from string, to []string, msg []byte) error {
	host, _, err := net.SplitHostPort(ms.server)
	if err != nil {
		return fmt.Errorf("invalid server address %q: %w", ms.server, err)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", ms.server)
	if err != nil {
		return err
	}
	defer conn.Close()

	// net/smtp has no context support: bound every read/write by the deadline
	// and break blocked I/O when ctx is cancelled.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	tlsConfig := ms.tlsConfigFor(host)
	if ms.implicitTLS {
		conn = tls.Client(conn, tlsConfig)
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()

	if ms.helloName != "" {
		if err := c.Hello(ms.helloName); err != nil {
			return err
		}
	}

	if !ms.implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}

	if ms.auth != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("smtp: server doesn't support AUTH")
		}
		if err := c.Auth(ms.auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}

	if err := c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return fmt.Errorf("rcpt %s: %w", addr, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (ms *MailSender) tlsConfigFor(host string) *tls.Config {
	cfg := &tls.Config{}
	if ms.tlsConfig != nil {
		cfg = ms.tlsConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return cfg
}
