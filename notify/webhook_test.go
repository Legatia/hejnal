package notify

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSend(t *testing.T) {
	var got map[string]string
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()

	w := Webhook{URL: srv.URL + "/services/T000/B000/secret", Client: srv.Client(), UserAgent: "hejnal-test"}
	if err := w.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "hello" || contentType != "application/json" {
		t.Errorf("sent %v with %q", got, contentType)
	}
}

func TestErrorsHideTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer srv.Close()
	w := Webhook{URL: srv.URL + "/services/secret-token", Client: srv.Client()}
	err := w.Send(context.Background(), "x")
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error = %v; want an error without the URL", err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens here now
	w = Webhook{URL: "http://" + addr + "/services/secret-token"}
	err = w.Send(context.Background(), "x")
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error = %v; want an error without the URL", err)
	}
}

func TestValidate(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://hooks.slack.com/services/x": true,
		"http://127.0.0.1:8080/hook":         true,
		"http://localhost/hook":              true,
		"http://hooks.example.com/x":         false,
		"ftp://hooks.example.com/x":          false,
		"not a url":                          false,
		"":                                   false,
	} {
		if err := (Webhook{URL: raw}).Validate(); (err == nil) != ok {
			t.Errorf("Validate(%q) = %v, want ok=%v", raw, err, ok)
		}
	}
}
