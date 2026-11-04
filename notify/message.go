package notify

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

// Message is a run summary for people: a title, short lines about what is
// new, and optionally the full fix list as Markdown.
type Message struct {
	Title string
	Lines []string
	// FixList is attached to emails when set.
	FixList []byte
}

// Notifier delivers messages to one channel.
type Notifier interface {
	// Name is a short label for logs and errors, such as "Slack".
	Name() string
	Notify(ctx context.Context, m Message) error
}

// Name implements Notifier.
func (w Webhook) Name() string { return "chat webhook" }

// Notify implements Notifier for Slack-compatible webhooks.
func (w Webhook) Notify(ctx context.Context, m Message) error {
	var b strings.Builder
	b.WriteString("*" + slackEscape(m.Title) + "*\n")
	for _, l := range m.Lines {
		b.WriteString(slackEscape(l) + "\n")
	}
	return w.Send(ctx, b.String())
}

// slackEscape escapes the characters Slack treats as markup.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// validateWebhookURL allows HTTPS, and plain HTTP only to this machine.
func validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return errors.New("notify: the webhook URL is not valid")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if loopback(u.Hostname()) {
			return nil
		}
	}
	return errors.New("notify: the webhook URL must use https")
}
