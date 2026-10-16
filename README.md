# exchangesmtp

Simple Go library for sending emails through on-premises Microsoft Exchange servers using LOGIN authentication.

## Why?

Exchange dropped support for PLAIN auth back in 2017. This library implements LOGIN auth mechanism that still works.

Exchange advertises `AUTH LOGIN` (plus `NTLM`/`GSSAPI`), but not `AUTH PLAIN`, so `smtp.PlainAuth` from the standard library can't be used.

No external dependencies — stdlib only.

## Install

```bash
go get github.com/d1n-go/exchange-smtp
```

The module moved from `github.com/demen1n/exchange-smtp` (versions up to v1.2.0 stay available there). To migrate, replace the import path; the API is unchanged.

## Usage

### Quick send

```go
qs := exchangesmtp.NewQuickSender(
    "user@company.com",           // username
    "password",                    // password
    "smtp.company.com:587",        // server
    "sender@company.com",          // from
    []string{"recipient@company.com"}, // to
)

err := qs.Send("Subject", "Body text")
```

### With attachments

```go
ms := exchangesmtp.NewMailSender("user@company.com", "password", "smtp.company.com:587")

mail := exchangesmtp.Mail{
    MT:      exchangesmtp.HTML,
    From:    "Отдел отчётности <reports@company.com>",
    To:      []string{"recipient@company.com"},
    Cc:      []string{"boss@company.com"},
    Bcc:     []string{"archive@company.com"},
    Subject: "Check this out",
    Body:    `<h1>Hello!</h1><img src="cid:logo">`,
    Headers: map[string]string{"Importance": "High"},
    Attachment: []exchangesmtp.AttachmentFile{
        {Name: "Отчёт.pdf", Body: fileBytes},
        {Name: "/var/reports/data.xlsx"}, // empty Body: read from disk
    },
    Inline: []exchangesmtp.InlineFile{
        {CID: "logo", Name: "logo.png", ContentType: "image/png", Body: logoBytes},
    },
}

err := ms.Send(mail)
```

### Options

```go
ms := exchangesmtp.NewMailSender(user, pass, "mail.corp.local:587",
    exchangesmtp.WithInsecureSkipVerify(),           // self-signed certificate
    exchangesmtp.WithHelloName("app01.corp.local"),   // EHLO name instead of "localhost"
    exchangesmtp.WithTimeout(30*time.Second),         // whole session, default 1 minute
)

err := ms.SendContext(ctx, mail)
```

| Option | Purpose |
|---|---|
| `WithTLSConfig(cfg)` | custom TLS: internal CA (`RootCAs`), old TLS versions, cipher suites |
| `WithInsecureSkipVerify()` | don't verify the server certificate |
| `WithImplicitTLS()` | TLS from the start (SMTPS, port 465) instead of STARTTLS |
| `WithHelloName(name)` | name sent in EHLO |
| `WithTimeout(d)` | limit for the whole SMTP session, `0` disables it |
| `WithAllowInsecureAuth()` | send credentials without TLS (trusted network only) |

## Features

- LOGIN authentication for Exchange
- STARTTLS and implicit TLS, custom TLS config, timeouts and `context.Context`
- Plain text and HTML emails
- To, Cc, Bcc, Reply-To, display names, custom headers
- File attachments and inline images
- UTF-8 everywhere: subject, display names, attachment names (RFC 2047, as Outlook does)
- Quoted-printable body encoding

## Old Exchange troubleshooting

**`x509: certificate signed by unknown authority`** — Exchange uses a self-signed certificate. Trust your CA with `WithTLSConfig(&tls.Config{RootCAs: pool})` or use `WithInsecureSkipVerify()`.

**`refusing LOGIN auth over unencrypted connection`** — the server didn't offer STARTTLS (often port 25 on an internal connector). Credentials would go in clear text; if the network is trusted, use `WithAllowInsecureAuth()`.

**TLS handshake failure (`protocol version not supported`, `handshake failure`)** — Exchange 2010/2013 on old Windows Server may support only TLS 1.0/1.1 or RSA key exchange, which Go disables by default:

```go
exchangesmtp.WithTLSConfig(&tls.Config{
    MinVersion: tls.VersionTLS10,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        tls.TLS_RSA_WITH_AES_128_CBC_SHA,
        tls.TLS_RSA_WITH_AES_256_CBC_SHA,
    },
})
```

**Send hangs and fails with `context deadline exceeded`** — wrong port or TLS mode: port 465 needs `WithImplicitTLS()`, ports 25/587 use STARTTLS.

**`504 5.7.4 Unrecognized authentication type`** — Basic auth is disabled on the receive connector; only NTLM/Kerberos are left.

**`535 5.7.3 Authentication unsuccessful`** — wrong credentials. Try both `user@company.com` and `DOMAIN\user` as the username.

**`550 5.7.60 SendAsDenied`** — the authenticated account has no "Send As" permission for the `From` address.

## Exchange Online

The library targets on-premises Exchange. Microsoft is retiring Basic authentication for SMTP AUTH in Exchange Online, where OAuth (XOAUTH2) is required.

## License

MIT
