# Security policy

Hejnal is a security tool, so we treat flaws in it seriously, especially
anything that could make it contact systems outside the authorised scope.

## Reporting a vulnerability

Please report privately through GitHub: open the **Security** tab of this
repository and choose **Report a vulnerability**. Do not open a public issue.

Include what you found, how to reproduce it and the version
(`hejnal version`). We aim to acknowledge reports within three working days.

## What counts

- Hejnal contacting a host, address or port outside the scope file, through
  DNS answers, redirects, certificate names or anything else.
- Anything that makes Hejnal send more than the documented ordinary
  requests, such as payloads, logins or path guessing.
- Leaks of secrets, such as webhook URLs or SMTP passwords in logs or error
  messages, or a secret found by `hejnal leaks` stored or printed in full.
- Ways around the token of `hejnal serve`, or a way for an API or MCP client
  to start a scan when runs were not allowed.
- Weak permissions on the state directory, or results written somewhere else.
- Crashes or resource exhaustion caused by a hostile server Hejnal probes.

Findings about the systems Hejnal checks belong to their owners, not here.

## Supported versions

Hejnal is pre-1.0. Fixes go into the latest release only.
