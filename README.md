# Hejnal

Hejnal watches your internet-facing systems and the code you ship for flaws
attackers are exploiting right now, and tells you what to fix first.

When a new flaw in a VPN gateway, firewall, mail server or CMS starts being
exploited, attackers scan the whole internet for it within days. Hejnal
keeps a map of what your organisation exposes. Each time CISA or ENISA adds a
flaw to its list of known exploited vulnerabilities, Hejnal checks your
systems for that product and puts it at the top of your fix list. In CI,
[`hejnal code scan`](#code-dependencies-infrastructure-and-images) applies
the same rule to dependencies, container images, infrastructure code and
secrets.

```console
$ hejnal run
Hejnal · Example Sp. z o.o.
First check · Open: 5 (critical 3 · high 0 · medium 1 · low 1)
• [critical] WordPress on www.example.com:443: CVE-2026-119977, CVE-2026-87902, CVE-2026-60137
• [critical] PHP on www.example.com:443: CVE-2026-109618, CVE-2026-109619
• [critical] Fortinet FortiGate SSL VPN on vpn.example.com:443: CVE-2025-61624, CVE-2025-25249, CVE-2025-68686, +2
• [medium] Jenkins admin interface reachable on ci.example.com:443
• [low] Jenkins on ci.example.com:443: CVE-2019-1003029, CVE-2019-1003030
Full list: hejnal report fixlist
Fix list written to .hejnal/fixlist.md.
```

The [fix list](examples/fix-list.en.md) then says for each item why it
matters, what to do, how sure Hejnal is and how to see it yourself.

The name comes from the *hejnał mariacki*, the bugle call played every hour
from St Mary's Church in Kraków. Legend has it a trumpeter once used it to warn
the city of an attack.

> **Status:** early. The open-source core works end to end. Hosted,
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
- possible **staging and test sites**: a name such as `staging.`, `dev.` or
  `preview.` whose front page answers without a password and shows it is a
  copy too: it asks search engines not to index it, calls itself a staging
  or test site, or has the same title as the live site's page. Hejnal
  guesses this, so the item says to check it;
- **mail records** that let others send email as your domain: no SPF record,
  an SPF record that lets any server through, and no or a watch-only DMARC
  policy. A subdomain without a DMARC record of its own is judged by its
  parent domain's, as receivers do, and a missing SPF record counts for
  less where an enforced DMARC policy already turns fake email away;
- **names whose server shows a certificate for other names**: a publicly
  trusted certificate that names none of the domains in your scope. If the
  names are yours, add them to the scope; if not, the name may point at a
  server you no longer control, such as a cloud address you gave back that
  someone else now rents, and security-rating companies count that server's
  flaws against you. Self-signed certificates, internal names and a hosting
  provider's own certificate on a name pointed at it are left out.

With `-checks` it also looks for exposed `.git` directories, `.env` files and
server status pages, and reads the scripts each front page loads from its own
site for **server secrets** shipped to every visitor, such as Stripe secret
keys, AWS secret keys and GitHub tokens. It reads the version of products
that hide it on the front page, such as WordPress, Grafana and Next.js, so
flaws that version does not have drop out. A run without `-checks` says when
that would shorten the list.
`hejnal leaks` finds secrets in your source code and accounts on your domains
in known data breaches. A REST API and an MCP server make the results
available to other tools and to AI assistants.

Every item says **how sure** Hejnal is and how you can **see it yourself**:
what answered and what it said, the version it showed, whether NVD lists
that version as affected and since when the flaw is known to be exploited,
with a ✓ for each step Hejnal saw and a ? for each it could not check from
outside, then the `curl`, `openssl` or `dig` command that shows the same
thing without Hejnal. The verdict is *confirmed*, *likely* (one step cannot
be checked from outside, such as a version the product hides) or *check it*
(something outside Hejnal's view may rule it out, such as fixes a Linux
distribution backports, whose names a certificate carries, or whether a
site named like a staging copy is one). The fix list starts with **where
to start**: the urgent items, most urgent first, with a rough effort for
each and in all, then the quick wins of 30 minutes or less.

**Hejnal is not a penetration test.** It never logs in, guesses passwords
or tries exploits, so it finds known problems anyone can see from outside
and misses what a tester would find by attacking. What it gives you is
continuous, dated evidence that you watch your exposure and fix what is
exploited, which is what SOC 2 (CC7.1), ISO 27001 (A.8.8) and NIS2 ask for
between yearly tests, and a way to make those tests cheaper by fixing the
obvious first.

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
  By default Hejnal sends one `GET /` per web service and follows its
  redirects on the same host. It tries the other of HTTP and HTTPS only when
  the first gets no answer or is told to use HTTPS. For a Next.js App Router
  site it asks for the same page once more, with `RSC: 1` and a random
  `_rsc` value, to tell a running server from static files. On other ports
  it only reads what the service says first.
- **Opt-in checks are fixed and few.** With `-checks`, Hejnal sends a few more
  ordinary `GET` requests per web service to fixed, well-known paths:
  `/.git/HEAD`, `/.env` and `/server-status`. It also requests one public
  version page (such as WordPress's `/feed/` or Grafana's `/api/health`) for
  recognised products that hide their version, and up to eight scripts the
  front page itself loads from the same site, which also give the version
  of Next.js. It never follows redirects for these. An exposed `.env` file is counted, never stored; a secret in a
  script is stored only as its start and length.
- **DNS is read, never changed.** Takeover checks read where each name
  points (its CNAME). Mail checks read the domain's MX and TXT records and
  its `_dmarc` record, and for a domain without one, the `_dmarc` records of
  its parent domains up to the first one found. A lookup that times out is
  never reported as a missing record.
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
sudo editor /etc/hejnal/scope.json       # your domains, and who authorised the checks; Hejnal refuses the example as it is
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

Hejnal uses only the Go standard library. It is tested on Linux and macOS.
Releases include Windows builds, which are not tested yet.

## Quick start

```sh
hejnal init -domain your-domain.pl -by "Your name, role"   # writes scope.json
hejnal run                         # discover, match and write .hejnal/fixlist.md
hejnal run -checks                 # the same, and read versions, exposed files and scripts
hejnal report fixlist -lang pl     # the fix list in Polish
hejnal report overview -o overview.html   # one page for decision-makers
hejnal report evidence -o evidence.html   # proof of monitoring, for insurers and auditors
hejnal report monthly              # this month: exposure, found, fixed, time to fix
hejnal report nis2                 # a NIS2 early-warning draft
```

`-by` names the person who confirms that you may test these systems; Hejnal
prints it on every run. `hejnal init` without flags writes an example to
edit instead, with single hosts, IP ranges and exclusions. Hejnal does not
run the example until its entries are replaced with your own.

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

Exit status: `0` when done, `1` on errors, `2` when new findings reach the
severity given with `-fail-on`. `hejnal run` exits 2 only when you set
`-fail-on`; `hejnal code scan` and `hejnal leaks scan` do so from high
upwards unless you set another level.

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
| `hejnal init` | Writes the scope file: ready to run with `-domain` and `-by`, otherwise an example to edit. |
| `hejnal run` | Discovers, matches, writes the fix list and notifies. |
| `hejnal discover` | Only finds hosts and identifies software; saves the inventory. |
| `hejnal feeds` | Downloads CISA's KEV catalog and ENISA's list into the cache. |
| `hejnal match` | Matches the saved inventory against the catalog. |
| `hejnal report fixlist\|overview\|evidence\|nis2\|monthly` | Prints a report from the saved runs. |
| `hejnal accept` | Accepts an item you checked, lists what is accepted or removes an acceptance. |
| `hejnal leaks scan\|breaches` | Finds secrets in source code, and accounts in known data breaches. |
| `hejnal code scan` | Checks dependencies, secrets, infrastructure code and container images, for CI. |
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
line that holds a harmless example with `hejnal:allow`, or leave whole
directories out with `-exclude`, such as `-exclude testdata`: a name matches
anywhere, a path with a slash, such as `docs/examples`, only under the
scanned directory. A value read from the environment, such as
`password = "$DB_PASSWORD"`, is not a secret and is not reported. Files over
2 MiB are not scanned, and the command says which.

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

## Code, dependencies, infrastructure and images

`hejnal code scan` checks what you build, from inside your CI, with the
same rule as the rest of Hejnal: what attackers exploit comes first, and
everything else waits quietly.

```sh
hejnal code scan .                                   # the current repository
hejnal code scan -exclude testdata -exclude docs/examples .   # without test fixtures and samples
hejnal code scan -image app.tar -format sarif -out hejnal.sarif .
docker save acme/api:1.4 -o api.tar && hejnal code scan -image api.tar
```

- **Dependencies.** It reads the lockfiles that pin exact versions: npm
  (`package-lock.json`), Yarn, pnpm, pip (`requirements*.txt` pins),
  Pipenv, Poetry, uv, PDM, Go (`go.mod`), Cargo, Bundler, Composer, Gradle
  lockfiles, Maven POMs with literal versions, and NuGet. Each package
  version is looked up in [OSV](https://osv.dev), the open advisory
  database. **Malicious packages** come first, then flaws on CISA's or
  ENISA's lists of exploited ones, then flaws EPSS rates likely to be
  exploited within 30 days. Every other advisory is low, whatever its own
  rating, because most are never exploited; `-all` lists them. Packages only
  development or tests use rank lower, except malware, which ran on every
  machine that installed it. Each item names the version that fixes it.
- **Container images.** An image saved with `docker save` or `podman save`,
  or as an OCI layout, is read layer by layer, without Docker: Debian,
  Ubuntu and Alpine packages (by their source package, as advisories name
  them), the modules compiled into Go programs, installed Python and Node.js
  packages, and lockfiles in the image. Other distributions are reported as
  not checked.
- **Secrets**, with the rules of `hejnal leaks scan`, and in the Git
  history with `-history`.
- **Infrastructure code.** Terraform files and `terraform show -json`
  plans, CloudFormation, Kubernetes manifests and Compose files, read by
  Hejnal's own small readers. A short list of settings that cause breaches:
  admin and database ports open to the internet, public buckets and
  databases, policies that allow every action on every resource, privileged
  containers and containers that mount the Docker socket or the host, and
  shared host namespaces. Only literal values count: a variable, a function
  or a `!Ref` never makes a finding, so every item is something the file
  says outright. Helm templates are skipped until rendered.

**What leaves the machine:** package names, ecosystems and versions, to OSV;
CVE IDs, to FIRST's EPSS API. Never code, file names or secrets. Output is
text, `-format json`, or `-format sarif` for GitHub code scanning and other
tools. `-fail-on high` (the default) makes the command exit 2 when an item
reaches that severity, to stop a build. Items accepted with `hejnal accept`
in the same state directory are shown as accepted and do not stop it.
`-exclude` leaves directories out, as in `hejnal leaks scan`.
`-save` keeps the result in the
state directory, so the daily fix list and alerts include it, scored again
each day: a dependency flaw that joins CISA's list tomorrow becomes urgent
tomorrow. `-upload <address>` sends the results, never the code, to Hejnal
Cloud with the token in `HEJNAL_UPLOAD_TOKEN`.

### In GitHub Actions

```yaml
name: Hejnal
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # to upload SARIF to code scanning
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: Legatia/hejnal@v0.7.0
        id: hejnal
        with:
          fail-on: high
          # exclude: testdata
          # images: api.tar
          # upload-url: https://your-hejnal-cloud
          # upload-token: ${{ secrets.HEJNAL_UPLOAD_TOKEN }}
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ steps.hejnal.outputs.sarif }}
```

The action downloads the release for the runner from GitHub, checks it
against the release's checksums, and runs it on the runner.

**Limits.** Matching is by exact version, as the lockfile records it;
Hejnal does not check whether your code calls the flawed function, and says
so on each item. Versions a parent POM or a BOM decides are not known from a
`pom.xml` alone: use Gradle lockfiles or check the built image. RPM-based
images (Fedora, RHEL, Amazon Linux) are not read yet.

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

## Reports

`hejnal report fixlist` prints the fix list again, `hejnal report monthly`
the month's exposure, findings, fixes and time to fix, and `hejnal report
nis2` a draft of a NIS2 early warning. Two more are made for readers outside
IT.

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
- **Controls it supports**, for auditors: SOC 2 CC7.1 and CC4.1, ISO/IEC
  27001:2022 A.8.8 and A.5.7, and NIS2 Article 21(2)(e), each with what in
  the report speaks to it. Whether a control is met stays the auditor's call.
- A SHA-256 fingerprint of the runs used, to check the report against them.

`-format json` writes the same evidence as data (schema
`https://github.com/Legatia/hejnal/evidence/v1`): the runs, every item's
exposure with its CVEs and dates, the accepted risks and the controls, for
compliance tools and audit workpapers.

It is not an audit or a certification, and it says so. Times to fix are
measured between runs, so they include the wait for the next run. `-since
2026-01-01` limits the period; Hejnal keeps the last 400 runs, over a year of
daily runs. Same format and options as the overview.

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
exploiting right now; make sure your version has the fix.** A port that only
redirects, such as port 80 to HTTPS, takes the version read on the service
it leads to.

Some flaws are in an application server, not in the pages it sends. For
those products Hejnal asks for the page a second time, the way a browser
does while it navigates the application, and a plain file server ignores
the difference. For Next.js's App Router it sends `RSC: 1` and a random
`_rsc` value, so a CDN that keeps a copy of the page passes the request on:
the Next.js server answers with its component payload (or a redirect adding
`_rsc`), while a static export on a file server or CDN sends the same HTML
page. An HTML answer still counts as the Next.js server when it carries
`X-Powered-By: Next.js` or one of the `x-nextjs-cache`, `x-nextjs-prerender`
and `x-nextjs-stale-time` headers, as a page a CDN kept from the server
does. A static export is still listed, marked as static files, but gets no
KEV finding: there is no server for the React Server Components flaw to
reach. Any other answer, including an error, counts as the application.

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

### Scores

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
subdomain takeover scores 80, a public bucket listing 75, a possible
staging site 50 and a folder listing 45. A certificate that names none of
your domains scores 55. Missing SPF scores 55, or 30 where an enforced
DMARC policy applies; an SPF record that lets any server through scores 55,
a missing DMARC policy 50 and a watch-only one 40.

Hejnal sees what a visitor sees from where it runs. It can miss products
behind a login page, on ports it does not check, or on hosts it was not told
about. Treat a clean report as "nothing obvious", not "nothing at all".

## Roadmap

- More products, and version pages for more of them
- Live cloud-account checks (public buckets, open security groups) beside
  the infrastructure-code rules
- RPM-based container images
- OSV version ranges for open-source products NVD has not analysed yet
- Detection-only confirmation checks for high-impact flaws
- Tests on Windows

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
from NVD, certificate transparency search from [crt.sh](https://crt.sh/), and
open-source advisories from [OSV](https://osv.dev), each under the terms of
the database it comes from (GitHub, PyPI, Go, RustSec, Debian, Ubuntu,
Alpine and others).
`hejnal leaks breaches` uses [Have I Been Pwned](https://haveibeenpwned.com/)
(CC BY 4.0).

This product uses the NVD API but is not endorsed or certified by the NVD.

## Po polsku

Hejnal pilnuje systemów Twojej organizacji widocznych z internetu i kodu,
który wdrażasz. Wykrywa podatności, które atakujący właśnie masowo
wykorzystują, i mówi, co naprawić najpierw.

- **Wykrywa** hosty w Twoich domenach i zakresach IP, także subdomeny z
  rejestrów certyfikatów (certificate transparency).
- **Rozpoznaje** ponad 250 produktów, m.in. bramy VPN i firewalle (Fortinet,
  Ivanti, Citrix, Palo Alto, Cisco), pocztę (Exchange, Zimbra, Roundcube),
  WordPress, PHP, GitLab i Jenkins. Robi to jednym zwykłym zapytaniem
  `GET /` na usługę; strona na Next.js App Router dostaje jeszcze jedno, z
  nagłówkiem `RSC: 1`.
- **Porównuje** je z katalogiem CISA KEV i z listą wykorzystywanych podatności
  ENISA w europejskiej bazie EUVD. Pokazuje identyfikatory EUVD, podatności,
  które zna tylko ENISA, i to, kiedy ENISA wpisała podatność wcześniej niż
  CISA. Gdy produkt pokazuje wersję, sprawdza w NVD, czy ta wersja jest
  podatna. Z opcją `-checks` odczytuje też wersję produktów, które jej nie
  pokazują na stronie głównej, m.in. WordPressa, Grafany i Next.js.
- **Sprawdza kod w CI:** `hejnal code scan` porównuje zależności, obrazy
  kontenerów, kod infrastruktury i sekrety z tym, co atakujący wykorzystują,
  i zapisuje wynik także jako SARIF dla GitHub code scanning.
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
potwierdził zgodę na testy: `hejnal init` zapisuje to z opcji `-by`. Nie loguje się, nie zgaduje haseł ani ścieżek i
nie używa exploitów.

```sh
hejnal init -domain twoja-domena.pl -by "Imię i nazwisko, stanowisko"
hejnal run -checks -lang pl
hejnal report fixlist -lang pl
hejnal report monthly -lang pl
hejnal accept -item 3f9a1c0d -reason "Wersja 6.8.3 ma poprawkę" -by "Anna Nowak"
hejnal leaks scan -history ~/kod/serwis
hejnal code scan -exclude testdata .
```

Sprawdzaj wyłącznie systemy, które należą do Ciebie, albo takie, na których
testowanie masz pisemną zgodę.
