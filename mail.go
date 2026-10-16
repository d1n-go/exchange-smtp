package exchangesmtp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type MailType int

const (
	PlainText MailType = iota
	HTML
)

var mailTypeNames = [...]string{"text/plain", "text/html"}

func (mt MailType) String() string {
	if int(mt) < 0 || int(mt) >= len(mailTypeNames) {
		return mailTypeNames[PlainText]
	}
	return mailTypeNames[mt]
}

const charset = "UTF-8"

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail email-address is valid
func ValidateEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// Mail is a struct for two types of email: plain text and html like.
type Mail struct {
	MT MailType

	From    string
	To      []string
	Cc      []string
	Subject string
	Body    string

	Attachment []AttachmentFile
	Inline     []InlineFile // для inline-картинок
}

type AttachmentFile struct {
	Name        string
	ContentType string
	Body        []byte
}

type InlineFile struct {
	CID         string // content-ID for link in HTML (ex: "logo")
	Name        string
	ContentType string // ex: "image/png"
	Body        []byte
}

func (m *Mail) AllRecipients() []string {
	r := make([]string, 0, len(m.To)+len(m.Cc))
	r = append(r, m.To...)
	r = append(r, m.Cc...)
	return r
}

// maxLineLen is the recommended header line length (RFC 5322 2.1.1).
const maxLineLen = 78

// writeHeader writes "Name: value" and folds value at spaces so that lines
// stay within maxLineLen where possible. Exchange truncates or rejects header
// lines longer than 998 characters, which a long encoded subject easily hits.
func writeHeader(msg *bytes.Buffer, name, value string) {
	msg.WriteString(name)
	msg.WriteString(": ")
	lineLen := len(name) + 2
	for i, word := range strings.Split(value, " ") {
		if i > 0 {
			if lineLen+1+len(word) > maxLineLen {
				msg.WriteString("\r\n")
				lineLen = 0
			}
			msg.WriteByte(' ')
			lineLen++
		}
		msg.WriteString(word)
		lineLen += len(word)
	}
	msg.WriteString("\r\n")
}

// sanitize strips CR and LF to prevent header injection.
var sanitize = strings.NewReplacer("\r", "", "\n", "").Replace

// encodeFileName prepares a file name for a quoted name/filename parameter:
// drops the directory part, RFC 2047-encodes non-ASCII names (the form
// Outlook and Exchange themselves produce) and escapes quotes.
func encodeFileName(name string) string {
	name = sanitize(name)
	if name != "" {
		name = filepath.Base(name)
	}
	name = mime.BEncoding.Encode("utf-8", name)
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(name)
}

// generateBoundary creates a random MIME boundary
func generateBoundary() string {
	var buf [16]byte
	rand.Read(buf[:])
	return fmt.Sprintf("boundary-%x", buf[:])
}

func (m *Mail) ToBytes() ([]byte, error) {
	msg := bytes.NewBuffer(nil)

	if len(m.To) == 0 {
		return nil, errors.New("recipient list is empty")
	}

	if len(m.Body) == 0 {
		return nil, errors.New("email body is empty")
	}

	// from valid
	if !ValidateEmail(m.From) {
		return nil, fmt.Errorf("invalid From email address: %s", m.From)
	}

	// to valid
	for _, addr := range m.To {
		if !ValidateEmail(addr) {
			return nil, fmt.Errorf("invalid To email address: %s", addr)
		}
	}

	// cc valid
	for _, addr := range m.Cc {
		if !ValidateEmail(addr) {
			return nil, fmt.Errorf("invalid Cc email address: %s", addr)
		}
	}

	// write headers
	writeHeader(msg, "From", m.From)
	writeHeader(msg, "To", strings.Join(m.To, ", "))
	if len(m.Cc) > 0 {
		writeHeader(msg, "Cc", strings.Join(m.Cc, ", "))
	}
	writeHeader(msg, "Subject", mime.BEncoding.Encode("utf-8", m.Subject))
	writeHeader(msg, "MIME-Version", "1.0")

	boundary := generateBoundary()
	hasAttachments := len(m.Attachment) > 0
	hasInline := len(m.Inline) > 0

	if hasAttachments || hasInline {
		msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n\r\n", boundary))
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	}

	// if exists inline-files, we need multipart/related
	if hasInline {
		relatedBoundary := generateBoundary()
		msg.WriteString(fmt.Sprintf("Content-Type: multipart/related; boundary=%s\r\n\r\n", relatedBoundary))
		msg.WriteString(fmt.Sprintf("--%s\r\n", relatedBoundary))

		// write body
		msg.WriteString(fmt.Sprintf("Content-Type: %s; charset=%s\r\n", m.MT.String(), charset))
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")

		qp := quotedprintable.NewWriter(msg)
		_, err := qp.Write([]byte(m.Body))
		if err != nil {
			return nil, err
		}
		err = qp.Close()
		if err != nil {
			return nil, err
		}

		// add inline files
		for _, file := range m.Inline {
			msg.WriteString(fmt.Sprintf("\r\n--%s\r\n", relatedBoundary))

			contentType := sanitize(file.ContentType)
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			name := encodeFileName(file.Name)
			cid := sanitize(file.CID)

			writeHeader(msg, "Content-Type", fmt.Sprintf("%s; name=\"%s\"", contentType, name))
			writeHeader(msg, "Content-Transfer-Encoding", "base64")
			writeHeader(msg, "Content-ID", "<"+cid+">")
			writeHeader(msg, "Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", name))

			if err := m.writeBytes(msg, file.Body); err != nil {
				return nil, err
			}
		}
		msg.WriteString(fmt.Sprintf("\r\n--%s--\r\n", relatedBoundary))
	} else {
		// write body (without inline)
		msg.WriteString(fmt.Sprintf("Content-Type: %s; charset=%s\r\n", m.MT.String(), charset))
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")

		qp := quotedprintable.NewWriter(msg)
		_, err := qp.Write([]byte(m.Body))
		if err != nil {
			return nil, err
		}
		err = qp.Close()
		if err != nil {
			return nil, err
		}
	}

	// add attachments
	if hasAttachments {
		for _, file := range m.Attachment {
			msg.WriteString(fmt.Sprintf("\r\n--%s\r\n", boundary))

			contentType := sanitize(file.ContentType)
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			name := encodeFileName(file.Name)
			writeHeader(msg, "Content-Type", fmt.Sprintf("%s; name=\"%s\"", contentType, name))
			writeHeader(msg, "Content-Transfer-Encoding", "base64")
			writeHeader(msg, "Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))

			if len(file.Body) > 0 {
				if err := m.writeBytes(msg, file.Body); err != nil {
					return nil, err
				}
			} else if file.Name != "" {
				if err := m.writeFile(msg, file.Name); err != nil {
					return nil, err
				}
			} else {
				return nil, fmt.Errorf("attachment has no body and no file name")
			}
		}
	}

	if hasAttachments || hasInline {
		msg.WriteString(fmt.Sprintf("\r\n--%s--\r\n", boundary))
	}

	return msg.Bytes(), nil
}

func (m *Mail) writeBytes(msg *bytes.Buffer, file []byte) error {
	payload := make([]byte, base64.StdEncoding.EncodedLen(len(file)))
	base64.StdEncoding.Encode(payload, file)
	msg.WriteString("\r\n")
	for index, line := 0, len(payload); index < line; index++ {
		msg.WriteByte(payload[index])
		if (index+1)%76 == 0 {
			msg.WriteString("\r\n")
		}
	}

	return nil
}

func (m *Mail) writeFile(msg *bytes.Buffer, fileName string) error {
	file, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}

	if err = m.writeBytes(msg, file); err != nil {
		return err
	}

	return nil
}
