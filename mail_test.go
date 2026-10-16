package exchangesmtp

import (
	"bytes"
	"encoding/base64"
	"mime"
	netmail "net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		email	string
		valid	bool
	}{
		{"user@example.com", true},
		{"user.name@example.com", true},
		{"user+tag@example.co.uk", true},
		{"invalid", false},
		{"@example.com", false},
		{"user@", false},
		{"user @example.com", false},
		{"", false},
		{"o'brien@example.com", true},
		{"admin@exchange", true},
		{"Ivan <ivan@example.com>", false},
		{"a@b.com\r\nBcc: evil@example.com", false},
	}

	for _, tt := range tests {
		result := ValidateEmail(tt.email)
		if result != tt.valid {
			t.Errorf("ValidateEmail(%q) = %v, want %v", tt.email, result, tt.valid)
		}
	}
}

func TestMail_ToBytes_PlainText(t *testing.T) {
	mail := Mail{
		MT:		PlainText,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Test Subject",
		Body:		"This is a plain text body.",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(msg, []byte("Content-Type: text/plain")) {
		t.Errorf("expected Content-Type to be text/plain, got: %s", msg)
	}
}

func TestMail_ToBytes_HTML(t *testing.T) {
	mail := Mail{
		MT:		HTML,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Test HTML Subject",
		Body:		"<h1>This is HTML content.</h1>",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(msg, []byte("Content-Type: text/html")) {
		t.Errorf("expected Content-Type to be text/html, got: %s", msg)
	}
}

func TestMail_ToBytes_Attachment(t *testing.T) {
	attachmentContent := []byte("This is the content of the file.")

	mail := Mail{
		MT:		PlainText,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Test Attachment",
		Body:		"Please see the attached file.",
		Attachment: []AttachmentFile{
			{
				Name:	"testfile.txt",
				Body:	attachmentContent,
			},
		},
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(msg, []byte("Content-Disposition: attachment; filename=\"testfile.txt\"")) {
		t.Errorf("expected attachment filename in email, got: %s", msg)
	}

	if !bytes.Contains(msg, []byte(base64.StdEncoding.EncodeToString(attachmentContent))) {
		t.Errorf("expected base64 encoded attachment content in email, got: %s", msg)
	}
}

func TestMail_ToBytes_InlineImage(t *testing.T) {
	imageContent := []byte("fake-image-data")

	mail := Mail{
		MT:		HTML,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Test Inline Image",
		Body:		`<html><body><img src="cid:logo" /></body></html>`,
		Inline: []InlineFile{
			{
				CID:		"logo",
				Name:		"logo.png",
				ContentType:	"image/png",
				Body:		imageContent,
			},
		},
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(msg, []byte("Content-ID: <logo>")) {
		t.Errorf("expected Content-ID in email, got: %s", msg)
	}

	if !bytes.Contains(msg, []byte("Content-Disposition: inline")) {
		t.Errorf("expected inline disposition, got: %s", msg)
	}

	if !bytes.Contains(msg, []byte("multipart/related")) {
		t.Errorf("expected multipart/related for inline images, got: %s", msg)
	}
}

func TestMail_ToBytes_EmptyTo(t *testing.T) {
	mail := Mail{
		MT:		PlainText,
		From:		"sender@example.com",
		Subject:	"Test Empty To",
		Body:		"This email has no recipients.",
	}

	_, err := mail.ToBytes()
	if err == nil || err.Error() != "recipient list is empty" {
		t.Errorf("expected error 'recipient list is empty', got: %v", err)
	}
}

func TestMail_ToBytes_EmptyBody(t *testing.T) {
	mail := Mail{
		MT:		PlainText,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Test Empty Body",
	}

	_, err := mail.ToBytes()
	if err == nil || err.Error() != "email body is empty" {
		t.Errorf("expected error 'email body is empty', got: %v", err)
	}
}

func TestMail_ToBytes_InvalidFromEmail(t *testing.T) {
	mail := Mail{
		MT:		PlainText,
		From:		"invalid-email",
		To:		[]string{"recipient@example.com"},
		Subject:	"Test",
		Body:		"Test body",
	}

	_, err := mail.ToBytes()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("invalid From email")) {
		t.Errorf("expected error about invalid From email, got: %v", err)
	}
}

func TestMail_ToBytes_InvalidToEmail(t *testing.T) {
	mail := Mail{
		MT:		PlainText,
		From:		"sender@example.com",
		To:		[]string{"invalid-email"},
		Subject:	"Test",
		Body:		"Test body",
	}

	_, err := mail.ToBytes()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("invalid To email")) {
		t.Errorf("expected error about invalid To email, got: %v", err)
	}
}

func TestMail_ToBytes_InvalidCcEmail(t *testing.T) {
	mail := Mail{
		MT:      PlainText,
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Cc:      []string{"invalid-cc"},
		Subject: "Test",
		Body:    "Test body",
	}

	_, err := mail.ToBytes()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("invalid Cc email")) {
		t.Errorf("expected error about invalid Cc email, got: %v", err)
	}
}

func TestMail_ToBytes_NoCcHeader(t *testing.T) {
	mail := Mail{
		MT:      PlainText,
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "No CC",
		Body:    "Body",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Contains(msg, []byte("Cc:")) {
		t.Errorf("expected no Cc header when Cc is empty, got: %s", msg)
	}
}

func TestMail_ToBytes_MultipleRecipients(t *testing.T) {
	mail := Mail{
		MT:		PlainText,
		From:		"sender@example.com",
		To:		[]string{"recipient1@example.com", "recipient2@example.com"},
		Subject:	"Test Multiple Recipients",
		Body:		"Test body",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(msg, []byte("To: recipient1@example.com, recipient2@example.com")) {
		t.Errorf("expected comma-separated recipients, got: %s", msg)
	}
}

func TestMail_ToBytes_AttachmentFromDisk(t *testing.T) {
	content := []byte("file content from disk")
	tmp := filepath.Join(t.TempDir(), "attach.txt")
	if err := os.WriteFile(tmp, content, 0600); err != nil {
		t.Fatal(err)
	}

	mail := Mail{
		MT:		PlainText,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Disk attachment",
		Body:		"See attached.",
		Attachment: []AttachmentFile{
			{Name: tmp},	// body пустой — должен читаться с диска
		},
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString(content)
	if !bytes.Contains(msg, []byte(encoded[:20])) {
		t.Errorf("expected base64 content from disk file, got: %s", msg)
	}
}

func TestMail_ToBytes_AttachmentEmptyBodyAndName(t *testing.T) {
	mail := Mail{
		MT:		PlainText,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Bad attachment",
		Body:		"See attached.",
		Attachment: []AttachmentFile{
			{},	// и Body, и Name пустые
		},
	}

	_, err := mail.ToBytes()
	if err == nil {
		t.Fatal("expected error for attachment with no body and no name")
	}
}

func TestMail_ToBytes_CIDHeaderInjection(t *testing.T) {
	mail := Mail{
		MT:		HTML,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Inline injection test",
		Body:		`<img src="cid:injected">`,
		Inline: []InlineFile{
			{
				CID:		"injected\r\nX-Injected: evil",
				Name:		"img.png",
				ContentType:	"image/png",
				Body:		[]byte("fake"),
			},
		},
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// инъекция заголовка означает, что \r\n попал в вывод как разрыв строки.
	// после санитизации весь мусор остаётся внутри значения Content-ID — отдельного заголовка нет.
	if bytes.Contains(msg, []byte("\r\nX-Injected:")) {
		t.Errorf("CID header injection not sanitized: %s", msg)
	}
}

func TestMail_ToBytes_InlineAndAttachment(t *testing.T) {
	imageContent := []byte("fake-image")
	fileContent := []byte("fake-attachment")

	mail := Mail{
		MT:		HTML,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Mixed content",
		Body:		`<img src="cid:logo">`,
		Inline: []InlineFile{
			{CID: "logo", Name: "logo.png", ContentType: "image/png", Body: imageContent},
		},
		Attachment: []AttachmentFile{
			{Name: "doc.pdf", ContentType: "application/pdf", Body: fileContent},
		},
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(msg, []byte("multipart/mixed")) {
		t.Errorf("expected multipart/mixed, got: %s", msg)
	}
	if !bytes.Contains(msg, []byte("multipart/related")) {
		t.Errorf("expected multipart/related, got: %s", msg)
	}
	if !bytes.Contains(msg, []byte("Content-ID: <logo>")) {
		t.Errorf("expected Content-ID for inline image, got: %s", msg)
	}
	if !bytes.Contains(msg, []byte(`filename="doc.pdf"`)) {
		t.Errorf("expected attachment filename, got: %s", msg)
	}
}

func TestMail_ToBytes_InlineEmptyContentType(t *testing.T) {
	mail := Mail{
		MT:		HTML,
		From:		"sender@example.com",
		To:		[]string{"recipient@example.com"},
		Subject:	"Inline fallback content type",
		Body:		`<img src="cid:img">`,
		Inline: []InlineFile{
			{CID: "img", Name: "img.bin", Body: []byte("data")},	// ContentType пустой
		},
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(msg, []byte("application/octet-stream")) {
		t.Errorf("expected fallback content type application/octet-stream, got: %s", msg)
	}
}

func TestLoginAuth_StartAndNext(t *testing.T) {
	auth := LoginAuth("user@example.com", "secret")

	proto, resp, err := auth.Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: true})
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if proto != "LOGIN" {
		t.Errorf("expected protocol LOGIN, got %s", proto)
	}
	if resp != nil {
		t.Errorf("expected nil initial response from Start, got %q", resp)
	}

	resp, err = auth.Next([]byte("Username:"), true)
	if err != nil || string(resp) != "user@example.com" {
		t.Errorf("Next Username: got %q, err %v", resp, err)
	}

	resp, err = auth.Next([]byte("Password:"), true)
	if err != nil || string(resp) != "secret" {
		t.Errorf("Next Password: got %q, err %v", resp, err)
	}

	_, err = auth.Next([]byte("Unknown:"), true)
	if err == nil {
		t.Error("expected error for unknown server prompt")
	}

	resp, err = auth.Next(nil, false)
	if err != nil || resp != nil {
		t.Errorf("Next(more=false) should return nil, nil; got %q, %v", resp, err)
	}
}

func TestQuickSender_Send(t *testing.T) {
	qs := NewQuickSender("user", "pass", "localhost:25", "from@example.com", []string{"to@example.com"})

	// quickSender.Send строит Mail и вызывает smtp.SendMail.
	// без живого сервера проверяем только что ошибка содержит сетевую причину,
	// а не панику или внутренний сбой сборки сообщения.
	err := qs.Send("Subject", "Body")
	if err == nil {
		t.Fatal("expected connection error to localhost:25")
	}
}

func TestLoginAuth_RefusesWithoutTLS(t *testing.T) {
	info := &smtp.ServerInfo{Name: "mail.example.com", TLS: false}

	if _, _, err := LoginAuth("u", "p").Start(info); err == nil {
		t.Error("expected LoginAuth to refuse an unencrypted connection")
	}
	if _, _, err := LoginAuth("u", "p").Start(&smtp.ServerInfo{Name: "localhost"}); err != nil {
		t.Errorf("expected LoginAuth to allow localhost, got %v", err)
	}
	if _, _, err := InsecureLoginAuth("u", "p").Start(info); err != nil {
		t.Errorf("expected InsecureLoginAuth to allow an unencrypted connection, got %v", err)
	}
}

func TestMail_ToBytes_LongSubjectFolded(t *testing.T) {
	subject := strings.Repeat("Отчёт о продажах ", 15)
	mail := Mail{
		MT:      PlainText,
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Subject: subject,
		Body:    "Body",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	header, _, _ := strings.Cut(string(msg), "\r\n\r\n")
	// an encoded-word can't be split, so only the hard 998 limit is strict;
	// 78 is the target for lines that consist of several words.
	for _, line := range strings.Split(header, "\r\n") {
		if len(line) > maxLineLen+len("Subject: ") {
			t.Errorf("header line is %d chars: %q", len(line), line)
		}
	}
	if !strings.Contains(header, "?=\r\n =?") {
		t.Errorf("expected subject to be folded between encoded-words, got: %s", header)
	}

	// unfold and decode the Subject back
	decoded, err := new(mime.WordDecoder).DecodeHeader(headerValue(msg, "Subject"))
	if err != nil {
		t.Fatalf("decode subject: %v", err)
	}
	if decoded != subject {
		t.Errorf("subject round-trip mismatch:\n got %q\nwant %q", decoded, subject)
	}
}

func TestMail_ToBytes_SubjectHeaderInjection(t *testing.T) {
	mail := Mail{
		MT:      PlainText,
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "Hello\r\nBcc: evil@example.com",
		Body:    "Body",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Contains(msg, []byte("\r\nBcc:")) {
		t.Errorf("subject header injection not prevented: %s", msg)
	}
}

func TestMail_ToBytes_AttachmentFileName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"report.pdf", `filename="report.pdf"`},
		{"/var/reports/report.pdf", `filename="report.pdf"`},
		{`say "hi".txt`, `filename="say \"hi\".txt"`},
		{"Отчёт.pdf", `filename="=?utf-8?b?` + base64.StdEncoding.EncodeToString([]byte("Отчёт.pdf")) + `?="`},
	}

	for _, tt := range tests {
		mail := Mail{
			MT:         PlainText,
			From:       "sender@example.com",
			To:         []string{"recipient@example.com"},
			Subject:    "Attachment name",
			Body:       "See attached.",
			Attachment: []AttachmentFile{{Name: tt.name, Body: []byte("data")}},
		}

		msg, err := mail.ToBytes()
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", tt.name, err)
		}
		if !bytes.Contains(msg, []byte(tt.want)) {
			t.Errorf("%q: expected %s, got: %s", tt.name, tt.want, msg)
		}
	}
}

func TestMail_ToBytes_AttachmentFileNameRoundTrip(t *testing.T) {
	name := strings.Repeat("Длинное имя файла ", 5) + ".xlsx"
	mail := Mail{
		MT:         PlainText,
		From:       "sender@example.com",
		To:         []string{"recipient@example.com"},
		Subject:    "Attachment name",
		Body:       "See attached.",
		Attachment: []AttachmentFile{{Name: name, Body: []byte("data")}},
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// unfold headers and parse the attachment's Content-Disposition
	unfolded := strings.ReplaceAll(string(msg), "\r\n ", " ")
	_, rest, ok := strings.Cut(unfolded, "Content-Disposition: ")
	if !ok {
		t.Fatalf("no Content-Disposition in: %s", msg)
	}
	value, _, _ := strings.Cut(rest, "\r\n")
	_, params, err := mime.ParseMediaType(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	got, err := new(mime.WordDecoder).DecodeHeader(params["filename"])
	if err != nil {
		t.Fatalf("decode filename: %v", err)
	}
	if got != name {
		t.Errorf("filename round-trip mismatch:\n got %q\nwant %q", got, name)
	}
}

// headerValue returns the unfolded value of the first top-level header name.
func headerValue(msg []byte, name string) string {
	header, _, _ := strings.Cut(string(msg), "\r\n\r\n")
	unfolded := strings.ReplaceAll(header, "\r\n ", " ")
	for _, line := range strings.Split(unfolded, "\r\n") {
		if v, ok := strings.CutPrefix(line, name+": "); ok {
			return v
		}
	}
	return ""
}

func TestMail_ToBytes_DateAndMessageID(t *testing.T) {
	mail := Mail{
		MT:      PlainText,
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "Headers",
		Body:    "Body",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := netmail.ParseDate(headerValue(msg, "Date")); err != nil {
		t.Errorf("invalid Date header: %v", err)
	}
	if id := headerValue(msg, "Message-Id"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@example.com>") {
		t.Errorf("unexpected Message-Id: %q", id)
	}
}

func TestMail_ToBytes_DisplayNames(t *testing.T) {
	mail := Mail{
		MT:      PlainText,
		From:    "Иван Петров <ivan@example.com>",
		To:      []string{"Support <support@example.com>", "plain@example.com"},
		ReplyTo: "noreply@example.com",
		Subject: "Names",
		Body:    "Body",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	from, err := netmail.ParseAddress(headerValue(msg, "From"))
	if err != nil || from.Name != "Иван Петров" || from.Address != "ivan@example.com" {
		t.Errorf("From round-trip: got %+v, err %v", from, err)
	}
	if got := headerValue(msg, "To"); got != `"Support" <support@example.com>, plain@example.com` {
		t.Errorf("unexpected To: %q", got)
	}
	if got := headerValue(msg, "Reply-To"); got != "noreply@example.com" {
		t.Errorf("unexpected Reply-To: %q", got)
	}
}

func TestMail_Bcc(t *testing.T) {
	mail := Mail{
		MT:      PlainText,
		From:    "sender@example.com",
		To:      []string{"Recipient <to@example.com>"},
		Cc:      []string{"cc@example.com"},
		Bcc:     []string{"hidden@example.com"},
		Subject: "Bcc",
		Body:    "Body",
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Contains(msg, []byte("hidden@example.com")) {
		t.Errorf("Bcc address must not appear in the message: %s", msg)
	}

	want := []string{"to@example.com", "cc@example.com", "hidden@example.com"}
	if got := mail.AllRecipients(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("AllRecipients() = %v, want %v", got, want)
	}

	mail.Bcc = []string{"not-an-address"}
	if _, err := mail.ToBytes(); err == nil || !strings.Contains(err.Error(), "invalid Bcc email") {
		t.Errorf("expected invalid Bcc error, got %v", err)
	}
}

func TestMail_ToBytes_CustomHeaders(t *testing.T) {
	mail := Mail{
		MT:      PlainText,
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "Headers",
		Body:    "Body",
		Headers: map[string]string{
			"importance": "High",
			"X-Note":     "evil\r\nBcc: x@example.com",
			"Message-ID": "<fixed@example.com>",
		},
	}

	msg, err := mail.ToBytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := headerValue(msg, "Importance"); got != "High" {
		t.Errorf("unexpected Importance: %q", got)
	}
	if got := headerValue(msg, "Message-Id"); got != "<fixed@example.com>" {
		t.Errorf("Message-ID override ignored: %q", got)
	}
	if bytes.Contains(msg, []byte("\r\nBcc:")) {
		t.Errorf("header value injection not prevented: %s", msg)
	}

	for _, bad := range []map[string]string{
		{"Subject": "override"},
		{"Bad Name": "x"},
		{"X-Evil\r\nBcc": "x"},
	} {
		mail.Headers = bad
		if _, err := mail.ToBytes(); err == nil {
			t.Errorf("expected error for headers %q", bad)
		}
	}
}
