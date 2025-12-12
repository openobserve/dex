package server

import (
	"time"

	"github.com/wneessen/go-mail"
	"golang.org/x/exp/rand"
)

var stdNums = []byte("0123456789")

// copied from https://github.com/openobserve/casdoor/blob/master/object/verification.go#L357-L367
func getRandomCode(length int) string {
	var result []byte
	r := rand.New(rand.NewSource(uint64(time.Now().UnixNano())))
	for i := 0; i < length; i++ {
		result = append(result, stdNums[r.Intn(len(stdNums))])
	}
	return string(result)
}

func sendEmail(s *Server, to string, subj string, body string) error {
	// First we create a mail message
	m := mail.NewMsg()
	if err := m.From(s.SmtpSender); err != nil {
		return err
	}
	if err := m.To(to); err != nil {
		return err
	}
	m.Subject(subj)
	m.SetBodyString(mail.TypeTextHTML, body)

	var port mail.Option
	if s.SmtpPort != 0 {
		port = mail.WithPort(s.SmtpPort)
	} else {
		port = mail.WithPort(25)
	}
	// Secondly the mail client
	c, err := mail.NewClient(s.SmtpHost,
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		port,
		mail.WithUsername(s.SmtpUser), mail.WithPassword(s.SmtpPassword))
	if err != nil {
		return err
	}

	// Finally let's send out the mail
	if err := c.DialAndSend(m); err != nil {
		return err
	}
	return nil
}
