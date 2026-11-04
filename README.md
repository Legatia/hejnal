# Hejnal

Hejnal watches your internet-facing systems for software that attackers are
exploiting right now, and tells you what to fix first.

When a new flaw in a VPN gateway, firewall, mail server or CMS starts being
exploited, attackers scan the whole internet for it within days. Hejnal
keeps a map of what your organisation exposes. Each time CISA adds a flaw to
its catalog of known exploited vulnerabilities, Hejnal checks your systems for
that product and puts it at the top of your fix list.

The name comes from the *hejnał mariacki*, the bugle call played every hour
from St Mary's Church in Kraków. Legend has it a trumpeter once used it to warn
the city of an attack.

> **Status:** early (v0.1). The open-source core works end to end. Hosted,
> managed and partner (MSP) editions are planned on top of it.

## What it does

1. **Finds your systems.** Hejnal starts from the domains, hosts and IP ranges
   in your scope file. It adds subdomains found in certificate transparency
   logs and names from the certificates your servers present, then checks
   which web ports answer.
2. **Recognises the software.** It sends one ordinary request per web service.
   From the headers, cookies, page title and page markers it recognises over 50
   products attackers go after most: Fortinet, Ivanti, Citrix, Palo Alto,
   Cisco, SonicWall and Check Point gateways; Exchange, Zimbra and Roundcube;
   WordPress, Drupal and PHP; GitLab, Jenkins, Confluence and more.
3. **Matches it against what is exploited now.** It compares what it found
   with the [CISA Known Exploited Vulnerabilities
   catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   (KEV). It ranks each match by how recently the flaw was added, whether the
   system is an internet-facing gateway, ransomware use, CISA's call for
   forensic triage and the [FIRST EPSS](https://www.first.org/epss/)
   exploitation probability.
4. **Tells you what to do.** It writes a fix list in English or Polish and can
   post a chat message when something new appears. If a system was
   compromised, it can draft a NIS2 early warning.

It also flags expired or expiring TLS certificates and admin interfaces it can
reach, such as Jenkins, phpMyAdmin or a vCenter login.

See an [example fix list](examples/fix-list.en.md) (and [in
Polish](examples/fix-list.pl.md)).

## Safety and authorisation

Hejnal only contacts systems listed in your scope file. The scope file has to
name who confirmed that you may test them, when and on what basis. Hejnal
prints this every time it runs.

- **One gate for every connection.** Every connection Hejnal opens passes a
  single scope check. DNS answers, redirects and names in certificates cannot
  lead it outside the scope.
- **Discovered names get web ports only.** Hosts found under your domains are
  checked on ports 80 and 443, and only at public internet addresses or
  addresses your scope lists. A DNS record pointing at a private address is
  listed but never contacted. Hosts and ranges you list yourself are checked
  on the ports you configure.
- **Small ranges.** IP ranges are capped at 1,024 addresses, so a typo cannot
  become a large scan.
- **Detection only.** No logins, no password guessing, no path guessing, no
  exploit payloads. Hejnal sends one `GET /` per web service and follows
  redirects only when they stay inside the scope.
- **Private results.** The inventory and findings are written readable only
  by their owner (mode 0600), because they map your attack surface.

Only check systems you own or have written permission to test. Testing other
people's systems can be illegal.

## Install

You need [Go](https://go.dev/dl/) 1.24 or newer.

```sh
go install github.com/Legatia/hejnal/cmd/hejnal@latest
```

Or build from source:

```sh
git clone https://github.com/Legatia/hejnal.git
cd hejnal
go build -o hejnal ./cmd/hejnal
```

Hejnal uses only the Go standard library. It runs on Linux and macOS;
Windows is untested.

## Quick start

```sh
hejnal init                        # writes an example scope.json
$EDITOR scope.json                 # list your systems and who authorised the checks
hejnal run -scope scope.json       # discover, match and write .hejnal/fixlist.md
hejnal report fixlist -lang pl     # the fix list in Polish
hejnal report nis2                 # a NIS2 early-warning draft
```

A scope file looks like this ([example](examples/scope.example.json)):

```json
{
  "organization": "Example Sp. z o.o.",
  "authorization": {
    "confirmedBy": "Jan Kowalski, IT manager",
    "date": "2026-11-04",
    "statement": "We own these systems or have written permission from their owner to test them."
  },
  "domains": ["example.com"],
  "hosts": ["vpn.example.com"],
  "cidrs": ["203.0.113.0/29"],
  "exclude": ["legacy.example.com"],
  "ports": [80, 443, 8080, 8443]
}
```

| Field | Meaning |
|---|---|
| `organization` | Shown on every report. |
| `authorization` | Who confirmed you may test these systems, when, and the statement they confirmed. Required. |
| `domains` | The domain and all its subdomains. Subdomains are found through certificate transparency and checked on web ports only. |
| `hosts` | Single hostnames or IP addresses, checked on all configured ports. |
| `cidrs` | IP ranges, at most 1,024 addresses in total, checked on all configured ports. |
| `exclude` | Hostnames (with their subdomains), addresses or ranges never to contact. |
| `ports` | Ports for `hosts` and `cidrs`. Default: 80, 443, 8080, 8443. |

Unknown fields are rejected, so a misspelt key cannot silently change the
scope.

## Run it every day

`hejnal run` is made for cron or a systemd timer. It sends a chat message only
on the first run and when something new appears.

```cron
HEJNAL_WEBHOOK=https://hooks.slack.com/services/T000/B000/XXXX
17 7 * * *  cd /srv/hejnal && hejnal run -lang pl -fail-on high >> hejnal.log 2>&1
```

The webhook accepts any Slack-compatible incoming webhook, including Slack,
Mattermost and Rocket.Chat. Pass it in the `HEJNAL_WEBHOOK` environment
variable rather than on the command line, so it stays out of process lists.

Exit status: `0` when done, `1` on errors, `2` when `-fail-on` is set and new
findings reach that severity.

### Commands

| Command | What it does |
|---|---|
| `hejnal init` | Writes an example scope file. |
| `hejnal run` | Discovers, matches, writes the fix list and notifies. |
| `hejnal discover` | Only finds hosts and identifies software; saves the inventory. |
| `hejnal feeds` | Downloads the KEV catalog into the cache. |
| `hejnal match` | Matches the saved inventory against the catalog. |
| `hejnal report fixlist\|nis2` | Prints a report from the last run. |
| `hejnal rules` | Lists the products Hejnal recognises. |

Run `hejnal <command> -h` for flags. Useful ones: `-lang en|pl`, `-no-ct` to
skip certificate transparency, `-no-epss`, `-offline`, `-kev-file`,
`-concurrency` and `-timeout`.

### Files

Everything lives in the state directory (`.hejnal` by default, `-state` to
change it):

| File | Contents |
|---|---|
| `inventory.json` | Hosts, open services, certificates and recognised products. |
| `findings.json` | Findings from the last run. |
| `history/` | Earlier findings, used to tell what is new; the last 200 runs are kept. |
| `fixlist.md` | The fix list from the last `hejnal run`. |
| `cache/kev.json`, `cache/epss.json` | Downloaded feeds. KEV is refreshed after 6 hours, EPSS after a day. |

### Offline and air-gapped use

Download the catalog on a connected machine with `hejnal feeds`. Copy
`.hejnal/cache/kev.json` across, then run with `-offline` (or point
`-kev-file` at the copy). Discovery still needs network access to your own
systems, of course.

## How matching works, and its limits

The KEV catalog names the vendor and product of each flaw, but not the
affected versions. Many products also hide their version from visitors. So a
match means: **you run a product attackers are exploiting right now; make
sure your version has the fix.** When a product shows its version, Hejnal
prints it next to the vendor advisories so you can check quickly. Version-aware
matching is on the roadmap.

Each match gets a score from 0 to 100:

| Signal | Points |
|---|---|
| Base | 60 |
| Added to KEV in the last 30 days / 90 days / over a year ago | +20 / +10 / −20 |
| Internet-facing gateway or remote-access product | +10 |
| Known use in ransomware campaigns | +10 |
| CISA asks for forensic triage | +5 |
| EPSS probability | up to +10 |

Scores of 85 and above are *fix now*, 70 to 84 *this week*, 50 to 69 *this
month*, and anything lower *later*. Expired certificates score 70, certificates
expiring within 21 days 50 and reachable admin interfaces 55.

Hejnal sees what a visitor sees from where it runs. It can miss products
behind a login page, on ports it does not check, or on hosts it was not told
about. Treat a clean report as "nothing obvious", not "nothing at all".

## Roadmap

- Version-aware matching using OSV and NVD version ranges
- Detection-only confirmation checks for high-impact flaws
- Checks for leaked credentials and exposed files
- REST API and an MCP server for assistants
- Signed releases with SBOMs (goreleaser and cosign)
- Hosted and managed editions, and a partner edition for MSPs

## Contributing

New fingerprint rules are the most useful contribution. See
[CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem in Hejnal
itself, see [SECURITY.md](SECURITY.md).

## Licence and data

Hejnal is licensed under the [Apache License 2.0](LICENSE).

It uses the CISA Known Exploited Vulnerabilities catalog (public domain, CC0),
EPSS scores from [FIRST](https://www.first.org/epss/) and certificate
transparency search from [crt.sh](https://crt.sh/).

## Po polsku

Hejnal pilnuje systemów Twojej organizacji widocznych z internetu. Wykrywa
oprogramowanie, które atakujący właśnie masowo wykorzystują, i mówi, co
naprawić najpierw.

- **Wykrywa** hosty w Twoich domenach i zakresach IP, także subdomeny z
  rejestrów certyfikatów (certificate transparency).
- **Rozpoznaje** ponad 50 produktów, m.in. bramy VPN i firewalle (Fortinet,
  Ivanti, Citrix, Palo Alto, Cisco), pocztę (Exchange, Zimbra, Roundcube),
  WordPress, PHP, GitLab i Jenkins. Robi to po jednym zwykłym zapytaniu na
  usługę.
- **Porównuje** je z katalogiem CISA KEV, czyli listą podatności aktywnie
  wykorzystywanych przez atakujących.
- **Pisze** listę poprawek po polsku lub angielsku, wysyła powiadomienia na
  czat i przygotowuje projekt wczesnego ostrzeżenia NIS2 (zgłoszenie do
  właściwego CSIRT, zwykle przez system S46).

[Przykładowa lista poprawek](examples/fix-list.pl.md).

Hejnal sprawdza tylko systemy z pliku zakresu. Plik musi wskazywać, kto i kiedy
potwierdził zgodę na testy. Nie loguje się, nie zgaduje haseł ani ścieżek i
nie używa exploitów.

```sh
hejnal init
hejnal run -scope scope.json -lang pl
hejnal report fixlist -lang pl
```

Sprawdzaj wyłącznie systemy, które należą do Ciebie, albo takie, na których
testowanie masz pisemną zgodę.
