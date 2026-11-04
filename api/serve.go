package api

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 32 << 10
	// shutdownTimeout is how long shutdown waits for requests in progress.
	shutdownTimeout = 10 * time.Second
)

// Serve listens on addr and serves h until ctx ends. Then it shuts down
// gracefully: it stops accepting connections, waits up to ten seconds for
// requests in progress and returns nil. It returns an error if it cannot
// listen or the server fails.
//
// Serve speaks plain HTTP. Bind it to localhost, or put a TLS proxy in front
// of it, so the token never crosses a network unencrypted.
func Serve(ctx context.Context, addr string, h http.Handler, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return serve(ctx, ln, h, logf)
}

func newServer(h http.Handler, logf func(string, ...any)) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          log.New(logWriter(logf), "", 0),
	}
}

func serve(ctx context.Context, ln net.Listener, h http.Handler, logf func(string, ...any)) error {
	srv := newServer(h, logf)
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok && !tcp.IP.IsLoopback() {
		logf("api: listening on %s over plain HTTP; use a TLS proxy if other machines can reach it", ln.Addr())
	} else {
		logf("api: listening on %s", ln.Addr())
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	logf("api: shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err := srv.Shutdown(sctx)
	if err != nil {
		srv.Close()
	}
	if serr := <-done; !errors.Is(serr, http.ErrServerClosed) && err == nil {
		err = serr
	}
	return err
}

// logWriter sends the HTTP server's own messages, such as TLS or protocol
// errors from clients, to logf.
type logWriter func(string, ...any)

func (l logWriter) Write(p []byte) (int, error) {
	l("api: %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
