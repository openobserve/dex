package server

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/wneessen/go-mail"
)

var stdNums = []byte("0123456789")

// codeRandReader is swappable only so tests can prove codes come from it.
var codeRandReader io.Reader = rand.Reader

// getRandomCode returns length uniformly random digits; it backs sign-up OTPs, csrf values and reset codes.
func getRandomCode(length int) string {
	result := make([]byte, length)
	n := big.NewInt(int64(len(stdNums)))
	for i := range result {
		// rand.Int rejects out-of-range samples, so digits carry no modulo bias.
		d, err := rand.Int(codeRandReader, n)
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		result[i] = stdNums[d.Int64()]
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
