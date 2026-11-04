// Package notify sends Hejnal's run summaries to chat.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Webhook posts messages to a Slack-compatible incoming webhook (Slack,
// Mattermost, Rocket.Chat and others that accept {"text": "..."}).
//
// Webhook URLs are secrets, so errors never include the URL.
type Webhook struct {
	URL       string
	Client    *http.Client
	UserAgent string
}

// Validate checks the URL. Only HTTPS is allowed, except plain HTTP to the
// local machine for testing.
func (w Webhook) Validate() error { return validateWebhookURL(w.URL) }

// Send posts text to the webhook.
func (w Webhook) Send(ctx context.Context, text string) error {
	if err := w.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(w.URL), bytes.NewReader(body))
	if err != nil {
		return errors.New("notify: could not build the webhook request")
	}
	req.Header.Set("Content-Type", "application/json")
	if w.UserAgent != "" {
		req.Header.Set("User-Agent", w.UserAgent)
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("notify: webhook request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify: webhook returned %s", resp.Status)
	}
	return nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
