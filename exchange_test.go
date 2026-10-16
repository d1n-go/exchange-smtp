package exchangesmtp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer is a minimal Exchange-like SMTP server: it advertises
// AUTH LOGIN only and optionally STARTTLS or implicit TLS.
type fakeServer struct {
	ln       net.Listener
	cert     tls.Certificate
	startTLS bool
	implicit bool
	noAuth   bool

	mu       sync.Mutex
	commands []string
	user     string
	pass     string
	rcpt     []string
	data     string
	authTLS  bool // whether AUTH happened over TLS
}

func newFakeServer(t *testing.T, cert tls.Certificate) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &fakeServer{ln: ln, cert: cert}
}

func (s *fakeServer) addr() string { return s.ln.Addr().String() }

func (s *fakeServer) serve(t *testing.T) {
	go func() {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := s.handle(conn); err != nil {
			t.Logf("fake server: %v", err)
		}
	}()
}

func (s *fakeServer) handle(conn net.Conn) error {
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{s.cert}}
	isTLS := false
	if s.implicit {
		conn = tls.Server(conn, tlsCfg)
		isTLS = true
	}
	tp := textproto.NewConn(conn)

	if err := tp.PrintfLine("220 fake ESMTP"); err != nil {
		return err
	}
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.commands = append(s.commands, line)
		s.mu.Unlock()

		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			ext := []string{"250-fake"}
			if s.startTLS && !isTLS {
				ext = append(ext, "250-STARTTLS")
			}
			if !s.noAuth {
				ext = append(ext, "250-AUTH LOGIN")
			}
			ext = append(ext, "250 OK")
			tp.PrintfLine("%s", strings.Join(ext, "\r\n"))
		case cmd == "STARTTLS":
			tp.PrintfLine("220 ready")
			conn = tls.Server(conn, tlsCfg)
			tp = textproto.NewConn(conn)
			isTLS = true
		case cmd == "AUTH LOGIN":
			tp.PrintfLine("334 VXNlcm5hbWU6")
			user, err := readBase64Line(tp)
			if err != nil {
				return err
			}
			tp.PrintfLine("334 UGFzc3dvcmQ6")
			pass, err := readBase64Line(tp)
			if err != nil {
				return err
			}
			s.mu.Lock()
			s.user, s.pass, s.authTLS = user, pass, isTLS
			s.mu.Unlock()
			tp.PrintfLine("235 2.7.0 Authentication successful")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			s.mu.Lock()
			s.rcpt = append(s.rcpt, strings.Trim(line[len("RCPT TO:"):], "<>"))
			s.mu.Unlock()
			tp.PrintfLine("250 OK")
		case cmd == "DATA":
			tp.PrintfLine("354 go ahead")
			b, err := tp.ReadDotBytes()
			if err != nil {
				return err
			}
			s.mu.Lock()
			s.data = string(b)
			s.mu.Unlock()
			tp.PrintfLine("250 queued")
		case cmd == "QUIT":
			tp.PrintfLine("221 bye")
			return nil
		default:
			tp.PrintfLine("250 OK")
		}
	}
}

func readBase64Line(tp *textproto.Conn) (string, error) {
	line, err := tp.ReadLine()
	if err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(line)
	return string(b), err
}

// selfSignedCert returns a certificate for 127.0.0.1, like the default
// self-signed certificate of an on-premises Exchange.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "exchange.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

func testMail() Mail {
	return Mail{
		MT:      PlainText,
		From:    "Sender <sender@example.com>",
		To:      []string{"to@example.com"},
		Cc:      []string{"cc@example.com"},
		Bcc:     []string{"bcc@example.com"},
		Subject: "Тест",
		Body:    "Body",
	}
}

func TestMailSender_STARTTLS(t *testing.T) {
	cert, leaf := selfSignedCert(t)

	t.Run("self-signed rejected by default", func(t *testing.T) {
		srv := newFakeServer(t, cert)
		srv.startTLS = true
		srv.serve(t)

		err := NewMailSender("user", "pass", srv.addr()).Send(testMail())
		var certErr *tls.CertificateVerificationError
		if !errors.As(err, &certErr) {
			t.Fatalf("expected certificate verification error, got %v", err)
		}
	})

	t.Run("trusted CA", func(t *testing.T) {
		srv := newFakeServer(t, cert)
		srv.startTLS = true
		srv.serve(t)

		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		ms := NewMailSender(`CORP\user`, "pass", srv.addr(), WithTLSConfig(&tls.Config{RootCAs: pool}))
		if err := ms.Send(testMail()); err != nil {
			t.Fatalf("send: %v", err)
		}

		srv.mu.Lock()
		defer srv.mu.Unlock()
		if srv.user != `CORP\user` || srv.pass != "pass" {
			t.Errorf("unexpected credentials %q / %q", srv.user, srv.pass)
		}
		if !srv.authTLS {
			t.Error("AUTH happened before STARTTLS")
		}
		if got := strings.Join(srv.rcpt, ","); got != "to@example.com,cc@example.com,bcc@example.com" {
			t.Errorf("unexpected RCPT list: %s", got)
		}
		if !strings.Contains(strings.Join(srv.commands, "\n"), "MAIL FROM:<sender@example.com>") {
			t.Errorf("expected bare envelope sender, got commands: %q", srv.commands)
		}
		if strings.Contains(srv.data, "bcc@example.com") {
			t.Errorf("Bcc leaked into message data: %s", srv.data)
		}
	})

	t.Run("insecure skip verify", func(t *testing.T) {
		srv := newFakeServer(t, cert)
		srv.startTLS = true
		srv.serve(t)

		if err := NewMailSender("user", "pass", srv.addr(), WithInsecureSkipVerify()).Send(testMail()); err != nil {
			t.Fatalf("send: %v", err)
		}
	})
}

func TestMailSender_ImplicitTLS(t *testing.T) {
	cert, _ := selfSignedCert(t)
	srv := newFakeServer(t, cert)
	srv.implicit = true
	srv.serve(t)

	ms := NewMailSender("user", "pass", srv.addr(), WithImplicitTLS(), WithInsecureSkipVerify())
	if err := ms.Send(testMail()); err != nil {
		t.Fatalf("send: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.authTLS || srv.user != "user" {
		t.Errorf("expected AUTH over implicit TLS, got user %q tls %v", srv.user, srv.authTLS)
	}
}

func TestMailSender_HelloName(t *testing.T) {
	cert, _ := selfSignedCert(t)
	srv := newFakeServer(t, cert)
	srv.startTLS = true
	srv.serve(t)

	ms := NewMailSender("user", "pass", srv.addr(), WithInsecureSkipVerify(), WithHelloName("app01.corp.local"))
	if err := ms.Send(testMail()); err != nil {
		t.Fatalf("send: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.commands[0] != "EHLO app01.corp.local" {
		t.Errorf("unexpected greeting %q", srv.commands[0])
	}
}

func TestMailSender_NoAuthAdvertised(t *testing.T) {
	cert, _ := selfSignedCert(t)
	srv := newFakeServer(t, cert)
	srv.noAuth = true
	srv.serve(t)

	err := NewMailSender("user", "pass", srv.addr()).Send(testMail())
	if err == nil || !strings.Contains(err.Error(), "doesn't support AUTH") {
		t.Fatalf("expected AUTH support error, got %v", err)
	}
}

// silentServer accepts connections and never answers, like a firewall
// black hole or an implicit-TLS port spoken to in plain SMTP.
func silentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	return ln.Addr().String()
}

func TestMailSender_Timeout(t *testing.T) {
	addr := silentServer(t)

	start := time.Now()
	err := NewMailSender("user", "pass", addr, WithTimeout(200*time.Millisecond)).Send(testMail())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Send took %v, timeout not applied", elapsed)
	}
}

func TestMailSender_ContextCancel(t *testing.T) {
	addr := silentServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	err := NewMailSender("user", "pass", addr).SendContext(ctx, testMail())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestQuickSender_Options(t *testing.T) {
	cert, _ := selfSignedCert(t)
	srv := newFakeServer(t, cert)
	srv.startTLS = true
	srv.serve(t)

	qs := NewQuickSender("user", "pass", srv.addr(), "from@example.com", []string{"to@example.com"}, WithInsecureSkipVerify())
	if err := qs.Send("Subject", "Body"); err != nil {
		t.Fatalf("send: %v", err)
	}
}
