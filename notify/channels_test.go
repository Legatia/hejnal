package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var msg = Message{
	Title:   "Hejnal · Przykład Sp. z o.o.",
	Lines:   []string{"First check · Open: 2", "• [critical] PHP on www.example.com:443: CVE-2026-109618"},
	FixList: []byte("# Lista poprawek Hejnal\n\nZażółć gęślą jaźń\n"),
}

func TestTeams(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	if err := (Teams{URL: srv.URL + "/workflows/secret", Client: srv.Client()}).Notify(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	att := got["attachments"].([]any)[0].(map[string]any)
	if got["type"] != "message" || att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("payload = %v", got)
	}
	body := att["content"].(map[string]any)["body"].([]any)
	if len(body) != 3 || body[0].(map[string]any)["text"] != msg.Title || body[2].(map[string]any)["text"] != msg.Lines[1] {
		t.Errorf("card body = %v", body)
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer fail.Close()
	err := (Teams{URL: fail.URL + "/workflows/secret-token", Client: fail.Client()}).Notify(context.Background(), msg)
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error = %v; want an error without the URL", err)
	}
	if err := (Teams{URL: "http://teams.example.com/x"}).Validate(); err == nil {
		t.Error("plain HTTP to a remote host was accepted")
	}
}

// fakeSMTP is a minimal plain SMTP server on the loopback interface.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	from string
	rcpt []string
	data string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	reply := func(s string) { io.WriteString(c, s+"\r\n") }
	reply("220 test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			reply("250 test")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from = strings.TrimSpace(line[len("MAIL FROM:"):])
			f.mu.Unlock()
			reply("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, strings.TrimSpace(line[len("RCPT TO:"):]))
			f.mu.Unlock()
			reply("250 OK")
		case cmd == "DATA":
			reply("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			reply("250 queued")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 OK")
		}
	}
}

func TestEmail(t *testing.T) {
	srv := newFakeSMTP(t)
	port, _ := strconv.Atoi(srv.ln.Addr().(*net.TCPAddr).AddrPort().String()[len("127.0.0.1:"):])
	e := Email{
		Host:    "127.0.0.1",
		Port:    port,
		From:    "Hejnal <hejnal@example.com>",
		To:      []string{"it@example.com", "Anna Nowak <anna@example.com>"},
		Timeout: 5 * time.Second,
	}
	if err := e.Notify(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.from != "<hejnal@example.com>" || len(srv.rcpt) != 2 {
		t.Errorf("envelope = %q %q", srv.from, srv.rcpt)
	}
	m, err := mail.ReadMessage(strings.NewReader(srv.data))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if subject != msg.Title {
		t.Errorf("subject = %q", subject)
	}
	_, params, _ := mime.ParseMediaType(m.Header.Get("Content-Type"))
	mr := multipart.NewReader(m.Body, params["boundary"])
	text, _ := mr.NextPart()
	body, _ := io.ReadAll(text)
	if !strings.Contains(string(body), "CVE-2026-109618") {
		t.Errorf("body = %q", body)
	}
	att, err := mr.NextPart()
	if err != nil || att.FileName() != "fixlist.md" {
		t.Fatalf("attachment = %v, %v", att, err)
	}
	raw, _ := io.ReadAll(att)
	content, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(raw), "\r\n", ""))
	if err != nil || !strings.Contains(string(content), "Zażółć gęślą jaźń") {
		t.Errorf("attachment = %q", content)
	}
}

func TestEmailValidate(t *testing.T) {
	good := Email{Host: "smtp.example.com", From: "a@example.com", To: []string{"b@example.com"}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, e := range []Email{
		{From: "a@example.com", To: []string{"b@example.com"}},
		{Host: "smtp.example.com", From: "not an address", To: []string{"b@example.com"}},
		{Host: "smtp.example.com", From: "a@example.com"},
		{Host: "smtp.example.com", From: "a@example.com", To: []string{"b@example.com\r\nBcc: x@example.com"}},
		{Host: "smtp.example.com\r\n", From: "a@example.com", To: []string{"b@example.com"}},
	} {
		if err := e.Validate(); err == nil {
			t.Errorf("Validate(%+v) succeeded", e)
		}
	}
}
