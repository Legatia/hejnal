# Hejnal

Hejnal watches your internet-facing systems for software that attackers are
exploiting right now, and tells you what to fix first.

When a new flaw in a VPN gateway, firewall, mail server or CMS starts being
exploited, attackers scan the whole internet for it within days. Hejnal
keeps a map of what your organisation exposes. Each time CISA or ENISA adds a
flaw to its list of known exploited vulnerabilities, Hejnal checks your
systems for that product and puts it at the top of your fix list.

The name comes from the *hejnał mariacki*, the bugle call played every hour
from St Mary's Church in Kraków. Legend has it a trumpeter once used it to warn
the city of an attack.

> **Status:** early (v0.2). The open-source core works end to end. Hosted,
> managed and partner (MSP) editions are built on top of it as a separate
> commercial product.

## What it does

1. **Finds your systems.** Hejnal starts from the domains, hosts and IP ranges
   in your scope file. It adds subdomains found in certificate transparency
   logs and names from the certificates your servers present, then checks
   which ports answer.
2. **Recognises the software.** It sends one ordinary request per web service
   and reads the greeting of mail, file-transfer and other services. From the
   headers, cookies, page title, page markers and greetings it recognises over
   250 products attackers go after most: Fortinet, Ivanti, Citrix, Palo Alto,
   Cisco, Juniper, SonicWall and Check Point gateways; MikroTik, DrayTek,
   TP-Link and D-Link routers; Hikvision and Dahua cameras; Exchange, Zimbra
   and Exim; SAP, Oracle E-Business Suite, VMware ESXi and Veeam; WordPress,
   Drupal and PHP; GitLab, Jenkins, Confluence and more. `hejnal rules` lists
   them all.
3. **Matches it against what is exploited now.** It compares what it found
   with the [CISA Known Exploited Vulnerabilities
   catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   (KEV) and with the exploited vulnerabilities in ENISA's [European
   Vulnerability Database](https://euvd.enisa.europa.eu/) (EUVD). Findings
   show each flaw's EUVD ID, flaws only ENISA lists, and when ENISA listed a
   flaw before CISA did. When a product shows its version, Hejnal compares it with the
   affected versions recorded by [NVD](https://nvd.nist.gov/), so flaws your
   version is not affected by drop out of the way. It ranks each match by how
   recently the flaw was added, whether the system is an internet-facing
   gateway, ransomware use, CISA's call for forensic triage and the
   [FIRST EPSS](https://www.first.org/epss/) exploitation probability.
4. **Tells you what to do.** It writes a fix list in English or Polish and
   sends new findings to Slack, Microsoft Teams or email. Each month it can
   report what was found, what was fixed and how long fixes took. If a system
   was compromised, it can draft a NIS2 early warning.

It also flags expired or expiring TLS certificates and admin interfaces it can
reach, such as Jenkins, phpMyAdmin or a vCenter login. From what each front
page and the DNS already show, it finds:

- **subdomain takeovers**: a name that points at GitHub Pages, Heroku, S3 or
  another hosting service where nothing is set up any more, so anyone could
  claim it;
- storage buckets and web folders that **list their files**;
- **staging and test sites** (`staging.`, `dev.`, `preview.` and the like)
  that answer without a password;
- **mail records** that let others send email as your domain: no SPF record,
  an SPF record that lets any server through, and no or a watch-only DMARC
  policy.

With `-checks` it also looks for exposed `.git` directories, `.env` files and
server status pages, and reads the scripts each front page loads from its own
site for **server secrets** shipped to every visitor, such as Stripe secret
keys, AWS secret keys and GitHub tokens.
`hejnal leaks` finds secrets in your source code and accounts on your domains
in known data breaches. A REST API and an MCP server make the results
available to other tools and to AI assistants.

See an [example fix list](examples/fix-list.en.md) (and [in
Polish](examples/fix-list.pl.md)).

## Safety and authorisation

Hejnal only contacts systems listed in your scope file. The scope file has to
name who confirmed that you may test them, when and on what basis. Hejnal
prints this every time it runs.

- **One gate for every connection.** Every connection Hejnal opens passes a
  single check of the host, the address and the port. DNS answers, redirects
  and names in certificates cannot lead it outside the scope.
- **Discovered names get web ports only.** Hosts found under your domains are
  checked on ports 80 and 443, and only at public internet addresses or
  addresses your scope lists. A DNS record pointing at a private address is
  listed but never contacted. Hosts and ranges you list yourself are checked
  on the ports you configure.
- **Listed names stay off this machine.** A host you list by name may point at
  a private address, for checks from inside your network. It is never
  contacted at the machine Hejnal runs on, link-local addresses or cloud
  metadata services.
- **Exclusions cover machines, not just names.** Excluding a hostname also
  excludes the addresses it resolves to when the run starts. That way the
  machine is not reached under another name or through a range. Sites that
  share such an address, behind the same CDN for example, are skipped too and
  listed as not contacted.
- **Redirects stay put.** Hejnal follows a redirect only on the same host and
  to a port allowed for it, never with credentials in the URL. If a redirect
  points to another host in scope, that host gets its own check.
- **Small ranges.** IP ranges are capped at 1,024 addresses, so a typo cannot
  become a large scan.
- **Detection only.** No logins, no password guessing, no exploit payloads.
  By default Hejnal sends one `GET /` per web service.
- **Opt-in checks are fixed and few.** With `-checks`, Hejnal sends a few more
  ordinary `GET` requests per web service to fixed, well-known paths:
  `/.git/HEAD`, `/.env` and `/server-status`. It also requests one public
  version page (such as WordPress's `/feed/` or Grafana's `/api/health`) for
  recognised products that hide their version, and up to eight scripts the
  front page itself loads from the same site. It never follows redirects
  for these. An exposed `.env` file is counted, never stored; a secret in a
  script is stored only as its start and length.
- **DNS is read, never changed.** Mail checks read the domain's MX and TXT
  records and `_dmarc` record. A lookup that times out is never reported as
  a missing record.
- **Private results.** The inventory and findings are written readable only
  by their owner (mode 0600), because they map your attack surface.

Only check systems you own or have written permission to test. Testing other
people's systems can be illegal.

## Install

Download a release for Linux, macOS or Windows from the
[releases page](https://github.com/Legatia/hejnal/releases). Each release
signs `checksums.txt` with Sigstore and ships an SBOM per archive. To verify:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Legatia/hejnal/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

The bundle is in Sigstore's current format (v0.3), which needs cosign 3 or
later; cosign 2 rejects it.

### Linux packages with a daily timer

Each release also has `.deb`, `.rpm` and `.apk` packages. They install the
binary and a systemd timer that runs `hejnal run` every morning as an
unprivileged, sandboxed service, keeping its results in `/var/lib/hejnal`:

```sh
sudo apt install ./hejnal_<version>_linux_amd64.deb      # or: sudo dnf install ./hejnal_<version>_linux_amd64.rpm
sudo cp /usr/share/doc/hejnal/scope.example.json /etc/hejnal/scope.json
sudo editor /etc/hejnal/scope.json       # your domains, and who authorised the checks
sudo editor /etc/hejnal/hejnal.env       # webhooks, email, NVD key, extra flags
sudo systemctl enable --now hejnal.timer
sudo systemctl start hejnal.service      # run once now
sudo cat /var/lib/hejnal/fixlist.md
```

The service does nothing until `/etc/hejnal/scope.json` exists.

### Container image

```sh
docker run --rm -v "$PWD:/work" -w /work --user "$(id -u)" \
  ghcr.io/legatia/hejnal:latest run -scope scope.json
```

The image holds only the binary, for `linux/amd64` and `linux/arm64`.

### With Go

With [Go](https://go.dev/dl/) 1.26 or newer you can also install it directly:

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
hejnal report overview -o overview.html   # one page for decision-makers
hejnal report evidence -o evidence.html   # proof of monitoring, for insurers and auditors
hejnal report monthly              # this month: exposure, found, fixed, time to fix
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

Mail, file-transfer, SSH and message-broker servers are recognised by the
greeting they send when Hejnal connects, and MongoDB by its answer to a plain
web request; Hejnal never logs in to them. To have them checked, add their
ports to `ports`, for example `21`, `22`, `25`, `587`, `27017` and `61616`.

## Run it every day

`hejnal run` is made for cron or a systemd timer. It notifies only on the
first run and when something new appears. If a notification cannot be sent,
the run exits with status 1 and the next run reports the same findings again.

```cron
HEJNAL_WEBHOOK=https://hooks.slack.com/services/T000/B000/XXXX
HEJNAL_NVD_API_KEY=your-free-nvd-key
17 7 * * *  cd /srv/hejnal && hejnal run -lang pl -fail-on high >> hejnal.log 2>&1
```

Notification channels, configured through environment variables so secrets
stay out of process lists:

| Channel | Settings |
|---|---|
| Slack, Mattermost, Rocket.Chat | `HEJNAL_WEBHOOK` (or `-webhook`) |
| Microsoft Teams | `HEJNAL_TEAMS_WEBHOOK` (or `-teams-webhook`): a Workflows "post to a channel when a webhook request is received" URL |
| Email | `HEJNAL_EMAIL_TO` (or `-email-to`), `HEJNAL_SMTP_HOST`, `HEJNAL_SMTP_PORT` (587 by default; 465 for TLS), `HEJNAL_SMTP_USER`, `HEJNAL_SMTP_PASSWORD`, `HEJNAL_SMTP_FROM`. Hejnal refuses to send unencrypted. The fix list is attached. |

A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) in
`HEJNAL_NVD_API_KEY` makes version checks about ten times faster.

Exit status: `0` when done, `1` on errors, `2` when `-fail-on` is set and new
findings reach that severity.

Many findings ask a person to check something: "you run WordPress, which
attackers are exploiting; make sure your version has the fix". Each item in
the fix list has an ID. Once you have checked an item, accept it, and daily
runs stop raising it:

```sh
hejnal accept -item 3f9a1c0d -reason "Version 6.8.3 has the fix" -by "Anna Nowak"
hejnal accept -list              # what is accepted, by whom, why and until when
hejnal accept -remove 3f9a1c0d   # open the item again
```

An acceptance covers the findings open in the item when you accept it.
Alerts and the exit status leave them out, and the fix list moves them to an
"Accepted" section at the end. A new flaw in the same item still shows. An
acceptance lasts 90 days, or until the date you give with `-until`, at most a
year. Then the item is open again and reported as new.

To include leaked secrets and breached accounts, see
[below](#leaked-secrets-and-breached-accounts).

### Commands

| Command | What it does |
|---|---|
| `hejnal init` | Writes an example scope file. |
| `hejnal run` | Discovers, matches, writes the fix list and notifies. |
| `hejnal discover` | Only finds hosts and identifies software; saves the inventory. |
| `hejnal feeds` | Downloads CISA's KEV catalog and ENISA's list into the cache. |
| `hejnal match` | Matches the saved inventory against the catalog. |
| `hejnal report fixlist\|overview\|evidence\|nis2\|monthly` | Prints a report from the saved runs. |
| `hejnal accept` | Accepts an item you checked, lists what is accepted or removes an acceptance. |
| `hejnal leaks scan\|breaches` | Finds secrets in source code, and accounts in known data breaches. |
| `hejnal serve` | Serves the results over a REST API. |
| `hejnal mcp` | Serves the results to AI assistants over MCP. |
| `hejnal rules` | Lists the products Hejnal recognises. |

Run `hejnal <command> -h` for flags. Useful ones: `-lang en|pl`, `-checks`,
`-no-ct` to skip certificate transparency, `-no-epss`, `-no-nvd`, `-no-euvd`,
`-offline`, `-kev-file`, `-euvd-file`, `-concurrency` and `-timeout`.

### Files

Everything lives in the state directory (`.hejnal` by default, `-state` to
change it):

| File | Contents |
|---|---|
| `inventory.json` | Hosts, open services, certificates and recognised products. |
| `findings.json` | Findings from the last run. |
| `reported.json` | The findings people were last told about, used to tell what is new. |
| `accepted.json` | Items accepted with `hejnal accept`: which findings, why, by whom and until when. |
| `history/` | Findings from earlier runs; the last 400 are kept, over a year of daily runs. |
| `fixlist.md` | The fix list from the last `hejnal run`. |
| `leaks.json`, `breaches.json` | Saved secret scans (secrets partly hidden) and breach counts, included in the next run. |
| `leaks.key` | The private key for secret fingerprints. |
| `cache/kev.json`, `cache/euvd-kev.json`, `cache/euvd/`, `cache/epss.json`, `cache/nvd/` | Downloaded feeds. KEV is refreshed after 6 hours, ENISA's list once a day after ENISA publishes it at 07:00 UTC, EUVD records and NVD records after a week (NVD's after a day while NVD has not analysed a flaw yet), EPSS scores when they are more than two days old. |

### Offline and air-gapped use

Download the feeds on a connected machine with `hejnal feeds`. Copy
`.hejnal/cache/kev.json` and `.hejnal/cache/euvd-kev.json` across, then run
with `-offline` (or point `-kev-file` and `-euvd-file` at the copies). Discovery still needs network access to your own
systems, of course.

## Leaked secrets and breached accounts

Attackers do not always need a flaw. A cloud key committed to a repository, or
a password reused from a breached website, works just as well.

`hejnal leaks scan` looks for secrets in source code and settings files:
cloud and API keys, access tokens, private keys (PEM, SSH2 and PuTTY),
passwords in URLs and password assignments. Add `-history` to check every
commit of the repository too, because a secret deleted from the code stays
in the Git history. Name the repository's top directory, and have Git 2.31
or later. Scanning a repository you received from someone else is safe:
Git runs without Hejnal's settings and secrets, cannot fetch anything, and
ignores the repository's own settings that would run programs or hide
changes.

```sh
hejnal leaks scan -history ~/code/website ~/code/backend
```

Secrets are never stored or printed in full. Tokens with a public prefix
show it, such as `ghp_ab… (40 chars)`, and passwords show only their length.
The command exits with status 2 when it finds a secret of high severity or
above (`-fail-on` changes the level), so it can gate a CI pipeline. Mark a
line that holds a harmless example with `hejnal:allow`. Files over 2 MiB are
not scanned, and the command says which.

With `-save`, the result is kept in the state directory, so the fix list,
notifications and monthly report include it. Each saved scan replaces the
previous one, so pass all your repositories in one command. Secrets are
told apart by a fingerprint keyed with a private key kept in the state
directory, so the same secret is recognised across scans, while nobody
without the key can test guesses against a fingerprint.

`hejnal leaks breaches` asks [Have I Been Pwned](https://haveibeenpwned.com/)
which accounts on the scope's domains appear in known data breaches. It needs
an HIBP API key with a domain search subscription in `HEJNAL_HIBP_API_KEY`,
and each domain verified in your HIBP dashboard. Hejnal keeps only how many
accounts each breach exposed. `-accounts` prints which accounts, without
storing them, because they are personal data.

```cron
HEJNAL_HIBP_API_KEY=your-hibp-key
10 7 * * *  cd /srv/hejnal && hejnal leaks breaches > /dev/null; hejnal leaks scan -save -fail-on none /srv/repos/* > /dev/null; hejnal run -lang pl
```

## API and AI assistants

`hejnal serve` makes the saved results available over a REST API, for
dashboards, ticketing and scripts. Clients send the token from
`HEJNAL_API_TOKEN` as `Authorization: Bearer <token>`.

```sh
export HEJNAL_API_TOKEN=$(openssl rand -hex 32)
hejnal serve -addr 127.0.0.1:8080
curl -H "Authorization: Bearer $HEJNAL_API_TOKEN" http://127.0.0.1:8080/v1/groups?min_severity=high
```

| Endpoint | Returns |
|---|---|
| `GET /v1/health` | Status and version. The only endpoint that needs no token. |
| `GET /v1/findings` | Findings from the last run. Filters: `min_severity`, `kind`, `host`. |
| `GET /v1/groups` | Items to fix and accepted items, as in the fix list. Filter: `min_severity`. |
| `GET /v1/inventory` | Hosts, services and recognised products. |
| `GET /v1/changes` | What is new and what was resolved since the last notification. |
| `GET /v1/reports/fixlist`, `GET /v1/reports/nis2` | The reports as Markdown. Parameter: `lang`. |
| `POST /v1/runs`, `GET /v1/runs/{id}` | Start a scan of the scope and follow it. Only with `-allow-runs`. |

The API has no TLS of its own. Keep it on a local address, or put it behind a
reverse proxy that terminates TLS.

`hejnal mcp` lets AI assistants that support the [Model Context
Protocol](https://modelcontextprotocol.io/) read the results. Add it to the
assistant's MCP settings:

```json
{
  "mcpServers": {
    "hejnal": {
      "command": "hejnal",
      "args": ["mcp", "-state", "/srv/hejnal/.hejnal", "-lang", "pl"]
    }
  }
}
```

The assistant can then ask for a summary, the fix list, findings filtered by
severity, host or CVE, the inventory and a NIS2 draft. These tools only read.
With `-allow-runs -scope scope.json`, it can also start a scan.

## How matching works, and its limits

The KEV catalog names the vendor and product of each flaw, but not the
affected versions. When the product shows its version, Hejnal looks up the
flaw in NVD and compares the version with the affected ranges NVD's analysts
recorded:

| Result | What Hejnal does |
|---|---|
| Affected | Marks the flaw "version affected" and raises its score by 10. |
| Affected only on a platform | NVD says the flaw needs a platform Hejnal cannot see, such as Windows for CVE-2024-4577. The finding says so; the score stays. |
| Ruled out | The version is outside every affected range. The flaw drops to low, is left out of alerts and moves to "Probably fixed already". |
| Unknown | NVD has not analysed the flaw yet (common in the first days), or Hejnal cannot be sure: the server shows only part of the version (`Apache/2.4`), NVD lists pre-release builds of that number separately, or a range cannot be read. Nothing changes. |

Versions from Linux distribution packages (for example PHP from Ubuntu, or
Apache reporting `(Debian)`) are never confirmed this way, because
distributions backport fixes without changing the version number. The same
goes for products whose hotfixes keep the version number, such as Serv-U and
N-central, and for Exim, whose greeting looks the same in distribution
packages.

Without a version, a match means: **you run a product attackers are
exploiting right now; make sure your version has the fix.**

Some flaws are in an application server, not in the pages it sends. For
those products Hejnal asks for the page a second time, the way a browser
does while it navigates the application, and a plain file server ignores
the difference. For Next.js's App Router it sends `RSC: 1`: the Next.js
server answers with its component payload (or a redirect adding `_rsc`),
while a static export on a file server or CDN sends the same HTML page. A
static export is still listed, marked as static files, but gets no KEV
finding: there is no server for the React Server Components flaw to reach.
Any other answer, including an error, counts as the application.

### The overview for decision-makers

`hejnal report overview -o overview.html` writes one self-contained page for
people who decide rather than fix: a verdict, the five items to fix first, how
long attackers have been exploiting each flaw, what kinds of product the
organisation exposes, and how the check was done. It is HTML with no external
files or scripts; open it in a browser and print or save it as PDF (it is laid
out for A4). `-by "Your company"` names who prepared it, and `-lang pl`
writes it in Polish. When nothing matches, it says so plainly, with what was
checked, instead of an empty page.

### Evidence for insurers, auditors and customers

`hejnal report evidence -o evidence.html` turns the saved runs into proof
that the organisation monitors its internet-facing systems and fixes what is
found:

- **How regularly it checked:** runs, average and longest gap between them.
- **Exposure window:** for each product with exploited flaws, when the flaw
  was listed, when Hejnal first saw it, when a run found it fixed and how many
  days it stayed exposed. Items already there at the first run are marked
  "≥", since they were exposed for longer than Hejnal saw.
- **Answers for security questionnaires**, worded from the data alone: how
  often you scan, whether you track exploited flaws, how fast you fix them
  (median and within 7 and 30 days), and whether accepted risks are
  documented.
- **Month by month**, and the accepted risks with their reasons.
- A SHA-256 fingerprint of the runs used, to check the report against them.

It is not an audit or a certification, and it says so. Times to fix are
measured between runs, so they include the wait for the next run. `-since
2026-01-01` limits the period; Hejnal keeps the last 400 runs, over a year of
daily runs. Same format and options as the overview.

### CISA's and ENISA's lists

ENISA publishes its own list of exploited vulnerabilities in the EUVD, partly
from European CSIRTs such as CERT Polska. Most of it overlaps with CISA's
catalog, but not all of it:

- **EUVD IDs.** Every flaw on either list gets its EUVD ID in the fix list,
  the NIS2 draft, the API and `findings.json`.
- **Flaws only ENISA lists** are matched like CISA's, using the vendor and
  product ENISA names and the description from the flaw's EUVD record. They
  have no CISA due date or ransomware flag. Product names such as "Various"
  match only when the description names the product.
- **ENISA first.** When ENISA listed a flaw before CISA, the fix list says so,
  and the NIS2 draft gives the earlier date.
- CISA's own catalog decides which flaws CISA lists. A flaw ENISA's data marks
  as CISA's but CISA has since removed is left out.

ENISA's list is optional: if it cannot be downloaded, Hejnal uses its saved
copy, or CISA's catalog alone. `-no-euvd` turns it off.

Each match gets a score from 0 to 100:

| Signal | Points |
|---|---|
| Base | 60 |
| Added to KEV (or to ENISA's list, for flaws only ENISA lists) in the last 30 days / 90 days / over a year ago | +20 / +10 / −20 |
| Internet-facing gateway, remote-access product, network device or camera | +10 |
| Known use in ransomware campaigns | +10 |
| CISA asks for forensic triage | +5 |
| EPSS probability | up to +10 |

Scores of 85 and above are *fix now*, 70 to 84 *this week*, 50 to 69 *this
month*, and anything lower *later*. Expired certificates score 70, certificates
expiring within 21 days 50 and reachable admin interfaces 55. With `-checks`,
an exposed `.env` file scores 90, an exposed `.git` directory 75 and a public
server status page 50, and a server secret in a script 95. A possible
subdomain takeover scores 80, a public bucket listing 75, a staging site 50
and a folder listing 45. Missing SPF or an SPF record that lets any server
through scores 55, a missing DMARC policy 50 and a watch-only one 40.

Hejnal sees what a visitor sees from where it runs. It can miss products
behind a login page, on ports it does not check, or on hosts it was not told
about. Treat a clean report as "nothing obvious", not "nothing at all".

## Roadmap

- More products, and version pages for more of them
- OSV version ranges for open-source products NVD has not analysed yet
- Detection-only confirmation checks for high-impact flaws
- Packages for Debian, Ubuntu and RHEL, and a container image

Hosted, managed and partner (MSP) editions are a separate commercial product
built on this core.

## Contributing

New fingerprint rules are the most useful contribution. See
[CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem in Hejnal
itself, see [SECURITY.md](SECURITY.md).

## Licence and data

Hejnal is licensed under the [Apache License 2.0](LICENSE).

Some fingerprint markers were confirmed against ProjectDiscovery's
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT License).

It uses the CISA Known Exploited Vulnerabilities catalog (public domain, CC0),
ENISA's list of exploited vulnerabilities and EUVD records (Source: ENISA
European Vulnerability Database (EUVD), reused under [ENISA's legal
notice](https://www.enisa.europa.eu/about-enisa/legal-notice)), EPSS scores from [FIRST](https://www.first.org/epss/), affected-version data
from NVD and certificate transparency search from [crt.sh](https://crt.sh/).
`hejnal leaks breaches` uses [Have I Been Pwned](https://haveibeenpwned.com/)
(CC BY 4.0).

This product uses the NVD API but is not endorsed or certified by the NVD.

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
- **Porównuje** je z katalogiem CISA KEV i z listą wykorzystywanych podatności
  ENISA w europejskiej bazie EUVD. Pokazuje identyfikatory EUVD, podatności,
  które zna tylko ENISA, i to, kiedy ENISA wpisała podatność wcześniej niż
  CISA. Gdy produkt pokazuje wersję, sprawdza
  w NVD, czy ta wersja jest podatna.
- **Szuka wycieków:** sekretów w kodzie źródłowym (klucze API, tokeny, klucze
  prywatne) i kont z Twoich domen w znanych wyciekach danych (Have I Been
  Pwned).
- **Pisze** listę poprawek po polsku lub angielsku, wysyła powiadomienia na
  Slacka, Microsoft Teams lub e-mailem, przygotowuje raport miesięczny i
  projekt wczesnego ostrzeżenia NIS2 (zgłoszenie do właściwego CSIRT, zwykle
  przez system S46).
- **Udostępnia wyniki** przez REST API i serwer MCP dla asystentów AI.
- **Pamięta sprawdzone punkty:** każdy punkt listy ma identyfikator. Polecenie
  `hejnal accept` zapisuje, kto sprawdził punkt, dlaczego i do kiedy.
  Powiadomienia i kod wyjścia pomijają go wtedy przez 90 dni albo do daty z
  opcji `-until`, najwyżej przez rok. Nowa podatność w tym samym punkcie i tak
  się pokaże.

[Przykładowa lista poprawek](examples/fix-list.pl.md).

Hejnal sprawdza tylko systemy z pliku zakresu. Plik musi wskazywać, kto i kiedy
potwierdził zgodę na testy. Nie loguje się, nie zgaduje haseł ani ścieżek i
nie używa exploitów.

```sh
hejnal init
hejnal run -scope scope.json -lang pl
hejnal report fixlist -lang pl
hejnal report monthly -lang pl
hejnal accept -item 3f9a1c0d -reason "Wersja 6.8.3 ma poprawkę" -by "Anna Nowak"
hejnal leaks scan -history ~/kod/serwis
```

Sprawdzaj wyłącznie systemy, które należą do Ciebie, albo takie, na których
testowanie masz pisemną zgodę.
