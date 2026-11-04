package notify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
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

// slackEscape escapes the characters Slack treats as markup, and defuses
// mentions.
func slackEscape(s string) string {
	return defuseMentions(strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s))
}

// defuseMentions puts an invisible word joiner after every @, so text from
// scanned systems cannot ping @channel, @here, @all or @everyone in
// Mattermost, Rocket.Chat, Discord or Teams.
func defuseMentions(s string) string {
	return strings.ReplaceAll(s, "@", "@\u2060")
}

// teamsEscape keeps text from being read as Markdown links in Teams
// Adaptive Cards, which would let a hostile name hide where a link goes,
// and defuses mentions.
func teamsEscape(s string) string {
	s = strings.NewReplacer("](", "]\u200b(", "<", "\u2039", ">", "\u203a").Replace(s)
	return defuseMentions(s)
}

// noRedirects returns a copy of client that does not follow redirects: a
// webhook that redirects elsewhere could receive the message over plain
// HTTP or at another host.
func noRedirects(client *http.Client) *http.Client {
	c := http.Client{Timeout: 30 * time.Second}
	if client != nil {
		c = *client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// statusError explains an unexpected HTTP status from a channel.
func statusError(channel string, resp *http.Response) error {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("notify: %s answered with a redirect (%s), which Hejnal does not follow; use the final URL", channel, resp.Status)
	}
	return fmt.Errorf("notify: %s returned %s", channel, resp.Status)
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
