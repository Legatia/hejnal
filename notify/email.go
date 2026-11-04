package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// Email sends messages over SMTP. Port 465 uses TLS from the start; other
// ports must offer STARTTLS, except on this machine, so passwords and
// reports never cross the network unencrypted.
type Email struct {
	Host     string
	Port     int // default 587
	Username string
	Password string
	From     string
	To       []string
	Timeout  time.Duration // default 30 seconds

	tlsConfig *tls.Config // for tests
}

// Name implements Notifier.
func (e Email) Name() string { return "email" }

// Validate checks the settings.
func (e Email) Validate() error {
	if e.Host == "" {
		return errors.New("notify: email needs an SMTP host")
	}
	if strings.ContainsAny(e.Host, " /\r\n") {
		return errors.New("notify: the SMTP host is not valid")
	}
	if _, err := mail.ParseAddress(e.From); err != nil {
		return fmt.Errorf("notify: sender address: %v", err)
	}
	if len(e.To) == 0 {
		return errors.New("notify: email needs at least one recipient")
	}
	for _, to := range e.To {
		if _, err := mail.ParseAddress(to); err != nil {
			return fmt.Errorf("notify: recipient %q: %v", to, err)
		}
	}
	return nil
}

func (e Email) port() int {
	if e.Port == 0 {
		return 587
	}
	return e.Port
}

// Notify implements Notifier.
func (e Email) Notify(ctx context.Context, m Message) error {
	if err := e.Validate(); err != nil {
		return err
	}
	msg, err := e.compose(m, time.Now())
	if err != nil {
		return err
	}
	return e.send(ctx, msg)
}

// compose builds the MIME message: the summary as text, the fix list as an
// attachment.
func (e Email) compose(m Message, now time.Time) ([]byte, error) {
	from, _ := mail.ParseAddress(e.From)
	var to []string
	for _, t := range e.To {
		a, _ := mail.ParseAddress(t)
		to = append(to, a.String())
	}
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	header := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }
	header("From", from.String())
	header("To", strings.Join(to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", strings.NewReplacer("\r", " ", "\n", " ").Replace(m.Title)))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@hejnal>")
	header("MIME-Version", "1.0")
	header("Content-Type", `multipart/mixed; boundary="`+mw.Boundary()+`"`)
	buf.WriteString("\r\n")

	part, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/plain; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	qp := quotedprintable.NewWriter(part)
	fmt.Fprintf(qp, "%s\r\n\r\n", m.Title)
	for _, l := range m.Lines {
		fmt.Fprintf(qp, "%s\r\n", l)
	}
	if len(m.FixList) > 0 {
		fmt.Fprint(qp, "\r\nThe full fix list is attached.\r\n")
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	if len(m.FixList) > 0 {
		att, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {`text/markdown; charset=utf-8; name="fixlist.md"`},
			"Content-Disposition":       {`attachment; filename="fixlist.md"`},
			"Content-Transfer-Encoding": {"base64"},
		})
		if err != nil {
			return nil, err
		}
		enc := base64.StdEncoding.EncodeToString(m.FixList)
		for len(enc) > 76 {
			fmt.Fprintf(att, "%s\r\n", enc[:76])
			enc = enc[76:]
		}
		fmt.Fprintf(att, "%s\r\n", enc)
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e Email) send(ctx context.Context, msg []byte) error {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cfg := e.tlsConfig
	if cfg == nil {
		cfg = &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.port()))
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if e.port() == 465 {
		conn, err = (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("notify: email: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * timeout))
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("notify: email: %w", err)
	}
	defer c.Close()
	if e.port() != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(cfg); err != nil {
				return fmt.Errorf("notify: email: STARTTLS: %w", err)
			}
		} else if !loopback(e.Host) {
			return errors.New("notify: email: the SMTP server does not offer STARTTLS; refusing to send unencrypted")
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return fmt.Errorf("notify: email: login failed: %w", err)
		}
	}
	from, _ := mail.ParseAddress(e.From)
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("notify: email: %w", err)
	}
	for _, t := range e.To {
		a, _ := mail.ParseAddress(t)
		if err := c.Rcpt(a.Address); err != nil {
			return fmt.Errorf("notify: email: recipient %s: %w", a.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("notify: email: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("notify: email: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: email: %w", err)
	}
	return c.Quit()
}
