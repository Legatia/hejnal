package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Teams posts messages to a Microsoft Teams channel through a Workflows
// webhook ("Post to a channel when a webhook request is received"), as an
// Adaptive Card. Like other webhook URLs it is a secret, so errors never
// include it.
type Teams struct {
	URL       string
	Client    *http.Client
	UserAgent string
}

// Name implements Notifier.
func (t Teams) Name() string { return "Microsoft Teams" }

// Validate checks the URL.
func (t Teams) Validate() error { return validateWebhookURL(t.URL) }

type card struct {
	Type        string           `json:"type"`
	Attachments []cardAttachment `json:"attachments"`
}

type cardAttachment struct {
	ContentType string      `json:"contentType"`
	Content     cardContent `json:"content"`
}

type cardContent struct {
	Schema  string      `json:"$schema"`
	Type    string      `json:"type"`
	Version string      `json:"version"`
	Body    []textBlock `json:"body"`
}

type textBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Wrap     bool   `json:"wrap"`
	Weight   string `json:"weight,omitempty"`
	Size     string `json:"size,omitempty"`
	Spacing  string `json:"spacing,omitempty"`
	IsSubtle bool   `json:"isSubtle,omitempty"`
}

// Notify implements Notifier.
func (t Teams) Notify(ctx context.Context, m Message) error {
	if err := t.Validate(); err != nil {
		return err
	}
	body := []textBlock{{Type: "TextBlock", Text: teamsEscape(m.Title), Wrap: true, Weight: "Bolder", Size: "Medium"}}
	for _, l := range m.Lines {
		body = append(body, textBlock{Type: "TextBlock", Text: teamsEscape(l), Wrap: true, Spacing: "Small"})
	}
	payload, err := json.Marshal(card{
		Type: "message",
		Attachments: []cardAttachment{{
			ContentType: "application/vnd.microsoft.card.adaptive",
			Content: cardContent{
				Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
				Type:    "AdaptiveCard",
				Version: "1.4",
				Body:    body,
			},
		}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(t.URL), bytes.NewReader(payload))
	if err != nil {
		return errors.New("notify: could not build the Teams request")
	}
	req.Header.Set("Content-Type", "application/json")
	if t.UserAgent != "" {
		req.Header.Set("User-Agent", t.UserAgent)
	}
	resp, err := noRedirects(t.Client).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("notify: Teams request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError("Teams", resp)
	}
	return nil
}
