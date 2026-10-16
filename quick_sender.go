package exchangesmtp

// QuickSender sends plain text emails from a fixed sender to fixed recipients.
type QuickSender struct {
	ms   *MailSender
	from string
	to   []string
}

// NewQuickSender is constructor for QuickSender. opts are passed to NewMailSender.
func NewQuickSender(user, password, server, from string, to []string, opts ...Option) *QuickSender {
	return &QuickSender{
		ms:   NewMailSender(user, password, server, opts...),
		from: from,
		to:   to,
	}
}

// Send sends a plain text email with the given subject and body.
func (qs *QuickSender) Send(subject, body string) error {
	m := Mail{
		MT:      PlainText,
		From:    qs.from,
		To:      qs.to,
		Subject: subject,
		Body:    body,
	}
	return qs.ms.Send(m)
}
