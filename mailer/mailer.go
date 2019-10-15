package mailer

import (
	"bufio"
	"bytes"
	"net/smtp"
	"text/template"

	log "github.com/makkes/golib/logging"
	"github.com/makkes/services.makk.es/auth/persistence"
)

type ActivationMail struct {
	To    string
	ID    string
	Token string
}

type Mailer interface {
	SendActivationMail(to string, token string, id persistence.AccountID, tmpl string) error
}

type SMTPMailer struct {
	host     string
	port     string
	username string
	password string
}

type MockMailer struct {
}

func NewSMTPMailer(host, port, username, password string) Mailer {
	return &SMTPMailer{
		host:     host,
		port:     port,
		username: username,
		password: password,
	}
}

func NewMockMailer() Mailer {
	return &MockMailer{}
}

func (m *MockMailer) SendActivationMail(to string, token string, id persistence.AccountID, mailTmpl string) error {
	tmpl := template.Must(template.New("activationMail").Parse(mailTmpl))
	var bodyBuffer bytes.Buffer
	bodyWriter := bufio.NewWriter(&bodyBuffer)
	err := tmpl.Execute(bodyWriter, ActivationMail{
		To:    to,
		ID:    id.String(),
		Token: token,
	})
	if err != nil {
		return err
	}
	bodyWriter.Flush()
	log.Info("Sending activation mail to %s: %s", to, bodyBuffer.Bytes())
	return nil
}

func (m *SMTPMailer) SendActivationMail(to string, token string, id persistence.AccountID, mailTmpl string) error {
	tmpl := template.Must(template.New("activationMail").Parse(mailTmpl))
	var bodyBuffer bytes.Buffer
	bodyWriter := bufio.NewWriter(&bodyBuffer)
	err := tmpl.Execute(bodyWriter, ActivationMail{
		To:    to,
		ID:    id.String(),
		Token: token,
	})
	if err != nil {
		return err
	}
	bodyWriter.Flush()
	log.Debug("Sending activation mail to %s:\n%s", to, bodyBuffer.Bytes())
	err = smtp.SendMail(
		m.host+":"+m.port,
		smtp.PlainAuth(
			"",
			m.username,
			m.password,
			m.host,
		),
		"noreply@services.makk.es",
		[]string{to},
		bodyBuffer.Bytes(),
	)
	return err
}
