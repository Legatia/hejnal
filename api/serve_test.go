package api

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/state"
)

func TestServeShutsDownGracefully(t *testing.T) {
	h, err := NewHandler(Config{Store: state.Store{Dir: t.TempDir()}, Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &logs{}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, "127.0.0.1:0", h, l.logf) }()

	// Serve logs the address it listens on.
	listening := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`)
	var addr string
	for deadline := time.Now().Add(5 * time.Second); addr == ""; {
		if m := listening.FindStringSubmatch(l.String()); m != nil {
			addr = m[1]
		} else if time.Now().After(deadline) {
			t.Fatalf("Serve did not start:\n%s", l.String())
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if strings.Contains(l.String(), "plain HTTP") {
		t.Errorf("warned about plain HTTP on loopback:\n%s", l.String())
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health: %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v after shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the context ended")
	}
	if _, err := client.Get("http://" + addr + "/v1/health"); err == nil {
		t.Error("still serving after shutdown")
	}
}

func TestServeWarnsAboutPlainHTTPOnOtherInterfaces(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot listen on all interfaces: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := &logs{}
	if err := serve(ctx, ln, http.NotFoundHandler(), l.logf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(l.String(), "plain HTTP") {
		t.Errorf("no warning:\n%s", l.String())
	}
}

func TestServeReportsListenErrors(t *testing.T) {
	if err := Serve(context.Background(), "127.0.0.1:-1", http.NotFoundHandler(), nil); err == nil {
		t.Error("Serve accepted an invalid address")
	}
}

func TestServerTimeouts(t *testing.T) {
	srv := newServer(http.NotFoundHandler(), func(string, ...any) {})
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("timeouts not set: %+v", srv)
	}
	if srv.MaxHeaderBytes <= 0 || srv.ErrorLog == nil {
		t.Errorf("header limit or error log not set")
	}
}
