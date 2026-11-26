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
   Drupal and PHP; GitLab, Jenkins, Confluence and more. It also recognises
   the AI tools teams set up themselves: Ollama, Open WebUI, Flowise,
   Jupyter, Gradio, ComfyUI, Dify, Langflow and MLflow. `hejnal rules` lists
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
4. **Dates what goes out of support.** When a product shows its version,
   Hejnal looks up its release line on [endoflife.date](https://endoflife.date)
   for 24 products, among them nginx, Apache HTTP Server, PHP, Tomcat,
   WordPress, Drupal, Jenkins, Grafana, Confluence, Jira and RouterOS. A
   release past its end of support gets no more security fixes, so it is
   an item to fix this month; a release whose support ends within 90 days is
   an item to plan, with the date. Each item names the closest supported
   release and the newest. Linux distribution packages are left out, because
   the distribution keeps fixing its own release after the upstream project
   stops.
5. **Tells you what to do.** It writes a fix list in English or Polish and
   sends new findings to Slack, Microsoft Teams or email. Each month it can
   report what was found, what was fixed and how long fixes took. If a system
   was compromised, it can draft a NIS2 early warning. `hejnal issues` keeps
   a GitHub issue for every item, assigned to the system's owner and closed
   when a later run no longer finds the item.

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
available to other tools and to AI assistants, and let a coding assistant
ask whether the item it fixed is still found.

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
each and in all, then the quick wins of 30 minutes or less. It ends with
the dates **coming up** in the next 90 days: support that ends, certificates
about to expire and acceptances that run out.

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
- **Opt-in checks are fixed and few.** With `-checks`, and in `hejnal live`
  unless you pass `-no-checks`, Hejnal sends a few more ordinary `GET`
  requests per web service to fixed, well-known paths:
  `/.git/HEAD`, `/.env` and `/server-status`. It also requests one public
  version page (such as WordPress's `/feed/`, Grafana's `/api/health` or
  Ollama's `/api/version`) for recognised products that hide their version,
  and up to eight scripts the
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
hejnal report weekly               # the last 7 days: checks, newly exploited flaws, fixed, open
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
  "ports": [80, 443, 8080, 8443],
  "owners": [
    {"name": "Web team", "github": "anna-nowak", "systems": ["shop.example.com"]},
    {"name": "Network", "systems": ["vpn.example.com", "203.0.113.0/29"]}
  ]
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
| `owners` | Optional. Who looks after which systems: a `name`, a `github` login or both, and the `systems` as hostnames (each with its subdomains), addresses or ranges. Where two entries fit a system, the closer one wins. [`hejnal issues`](#issues-on-github) names the owner on each issue and assigns it to the login. |

Unknown fields are rejected, so a misspelt key cannot silently change the
scope.

Mail, file-transfer, SSH and message-broker servers are recognised by the
greeting they send when Hejnal connects, and MongoDB by its answer to a plain
web request; Hejnal never logs in to them. To have them checked, add their
ports to `ports`, for example `21`, `22`, `25`, `587`, `27017` and `61616`.

## Run it every day

`hejnal run` is made for cron or a systemd timer. It sends a message on the
first run, when something new appears and when an item is fixed. It calls an
item fixed only when the run sees what replaced it: the same product still
answers without the flaw or with a supported release, the certificate was
renewed, or the mail record was read and is now in order. A product that
merely stops showing, behind a maintenance page, say, a version the server
hides and a DNS lookup that times out are not reported as fixes. If a notification cannot be sent, the run
exits with status 1 and the next run reports the same findings again.

Once a week, on Monday by default, it also sends a short summary of the days
since the last one, even when nothing is new. If no run happened on Monday,
the next run sends it. If no check reached your systems all week, the
summary says so and shows what the last check that did found, rather than
reporting nothing open.

```text
Hejnal · Example Sp. z o.o. · week of 2026-11-16 to 2026-11-23
Checked on 7 of the last 7 days · Hosts: 12 · Services: 18 · Products recognised: 21
Flaws newly listed as exploited this week: 9. Hejnal checked each one against the software it found on your systems: none is affected.
Fixed this week: 2 · New this week: 0
Open: 3 (critical 0 · high 1 · medium 2 · low 0)
Oldest open item: Jenkins admin interface reachable on ci.example.com:443, open since 2026-10-02 (days open: 52)
Coming up: 2026-12-04 · TLS certificate expiring soon on mail.example.com:443
Full list: hejnal report fixlist
```

Choose the day with `-weekly friday`, or turn it off with `-weekly off`.
`hejnal report weekly` prints the same summary at any time.

Each run also compares the services that answer with what answered before,
and says what changed even when no finding is new:

- **new**: a service that answers for the first time, with what runs there
  and how its host was found (a certificate log, a redirect, a certificate
  one of your servers sent, your DNS provider's records);
- **gone**: a service that did not answer in two runs in a row, so one
  timeout is not news. When its name still resolves, the message says to
  remove the DNS record if the system is retired;
- **updated**: a product that shows a new version, such as nginx 1.24.0 →
  1.30.6.

```
Systems · new: 1 · gone: 1 · updated: 1
• New: api.example.com (443) · Grafana 12.3.1 · found in a certificate log
• Gone: old.example.com (80, 443) · no answer in the last two checks, but the name still resolves: if the system is retired, remove its DNS record
• Updated: nginx 1.24.0 → 1.30.6 on shop.example.com (80, 443)
```

The first run only records what answers. Hosts that leave the scope are
dropped without a word.

`hejnal systems` lists every system on record: its ports and products, the
first and the last day it answered, its open items and whether it still
answers. Above the table it names the systems that run AI tools, such as a
model server or a notebook:

```
**AI tools:** lab.example.com (Open WebUI, Ollama)
```

The JSON output, the API and the MCP server carry the same as `aiTools` on
each system. A system recorded by an earlier release of Hejnal is named once
it answers in another run.

`hejnal systems shop.example.com` prints the history of one, from
its first answer to the day it went away:

```
- 2026-10-20 · First answer · port 80, 443
- 2026-10-20 · Found in the first check, so it was there before: PHP on shop.example.com:443 · high · `ebc52a7e`
- 2026-11-10 · nginx 1.24.0 → 1.30.6 · port 80, 443
- 2026-11-10 · PHP 8.3.12 → 8.3.14 · port 443
- 2026-11-10 · Fixed: PHP on shop.example.com:443 · high · `ebc52a7e` · seen for 21.0 days
```

Above the timeline it lists the system's services and every item found on
it, with the day it was found, the day a run found it fixed and its status.
`-format json` writes the same as data. Items come from the saved runs, and
version changes are on record from the first run with this version on.

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
`-fail-on`; `hejnal live`, `hejnal code scan` and `hejnal leaks scan` do so
from high upwards unless you set another level.

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

### Right after a deploy

`hejnal live` checks one system the moment it goes live, without waiting for
the next daily run:

```sh
hejnal live -wait 2m https://app.your-domain.pl
```

It reads what answers at the address and its certificate, asks for the fixed
paths `-checks` uses (`/.git/HEAD`, `/.env`, `/server-status` and the
product's version page), and matches the products it recognises against the
lists of exploited flaws and the end-of-support dates. It prints what it saw
and the items to fix, and exits with status 2 when an item reaches `-fail-on`
(`high` unless set), so a pipeline can stop or roll back.

- **The scope file still decides.** The address has to be in the scope file.
  A name under one of your domains is checked on ports 80 and 443; to check
  another port, list the host under `hosts`.
- **Only that system is contacted**: the address you name, and a host in the
  scope it redirects to. Hejnal reads no certificate transparency logs and
  no mail records for it, and leaves the rest of the scope alone.
- **Nothing is saved** but the downloaded feeds. The record of the daily
  runs, their alerts and each system's history stay as they are. Items you
  accepted with `hejnal accept` are left out, as in a run.
- **It can wait for the deploy.** With `-wait`, Hejnal asks for the front
  page every five seconds until a website answers without a server error,
  and only then sends the other requests. When nothing answers in that time,
  or the answer is still a 5xx error, it exits with status 1.

The check looks at the front page and the fixed paths, not at a path in the
address you give. `-no-checks` keeps it to the front page. What only a full
run can see stays with the daily run: names nobody listed, mail records, and
a test copy recognised by having the same title as the live site.

**After a fix, ask about one item.** With `-item` and an item's ID, the
command says only whether that item is still found:

```sh
hejnal live -item 3f9a1c0d https://shop.your-domain.pl
```

It exits with status 2 while the item is found, 0 once it is not, and 1 when
this check cannot tell, such as for an item of another system or one only a
full run finds (mail records, breached accounts). An item that changed
without being fixed, such as a product updated to a version that still has
an exploited flaw, counts as found, and the answer names its new ID.
`hejnal code scan -item` does the same for an item in the code.

### Issues on GitHub

`hejnal issues` keeps one GitHub issue for every open item on the fix list,
so the work lands where your team already tracks it. Run it after
`hejnal run`: it reads the saved run and contacts only GitHub.

```sh
export HEJNAL_GITHUB_TOKEN=...                # a token that may read and write issues
hejnal issues -repo your-org/infra -dry-run   # print what would change
hejnal issues -repo your-org/infra
```

```
opened #41 · 3f9a1c0d · WordPress on shop.example.com:443 · Web team
closed #38 · ebc52a7e · PHP on shop.example.com:443 · no longer found
Issues in your-org/infra: 1 opened, 1 closed, 0 reopened, 6 open already.
```

Each issue has the item's priority, its owner from the scope file, a rough
effort, what to do and the command that shows the problem without Hejnal.
It ends with a **Fix and check** block, written so that a person or a coding
assistant handed the issue can act on it: for a dependency the package, the
installed version, the version that fixes it and the files that pin it; for
a system its address and the product; and the command that says whether the
item is still found, `hejnal code scan -item` or `hejnal live -item`. A
secret gets the file and line only, and mail records, breached accounts and
names left pointing at a hosting service get no block: the next run checks
those.
From then on the issue follows the runs:

- An item found for the first time gets an issue, assigned to the owner's
  GitHub login.
- When a later run no longer finds the item, its issue is closed as
  completed, with a comment that names the run.
- When the item is found again, the same issue is reopened.
- When you accept the item with `hejnal accept`, its issue is closed as not
  planned, with the reason and who accepted it. It is reopened if the
  acceptance ends and the item is still found.
- An issue you close yourself stays closed until the next run has checked
  the fix, and is reopened if that run still finds the item. One you close
  as not planned stays closed; record that decision with `hejnal accept`, so
  the reports show it too.

Hejnal writes an issue's text once and never overwrites it, so your edits
and comments stay. It finds its issues by their label: `hejnal`, or the one
you give with `-label`. Give each scope its own label when several share a
repository. `-min-severity high` opens issues for high and critical items
only, and `-max-new` (50 by default) limits how many are opened in one go;
the rest follow next time. When a run reached no services at all, no issue
is closed.

The issues say which of your systems have open items, so Hejnal refuses a
public repository unless you pass `-public`. The token comes from
`HEJNAL_GITHUB_TOKEN`, or from `GITHUB_TOKEN` as GitHub Actions sets it,
never from a flag. In a workflow, the repository is the one the workflow
runs in:

```yaml
permissions:
  contents: read
  issues: write
steps:
  - uses: actions/checkout@v7
  # install hejnal, then:
  - run: hejnal run -scope scope.json
  - run: hejnal issues
    env:
      GITHUB_TOKEN: ${{ github.token }}
```

On GitHub Enterprise Server, set `GITHUB_API_URL` to its API address;
Actions does that itself.

To include leaked secrets and breached accounts, see
[below](#leaked-secrets-and-breached-accounts).

### Commands

| Command | What it does |
|---|---|
| `hejnal init` | Writes the scope file: ready to run with `-domain` and `-by`, otherwise an example to edit. |
| `hejnal run` | Discovers, matches, writes the fix list and notifies. |
| `hejnal discover` | Only finds hosts and identifies software; saves the inventory. |
| `hejnal live <url>` | Checks one system that is live, such as right after a deploy; saves nothing. |
| `hejnal feeds` | Downloads CISA's KEV catalog and ENISA's list into the cache. |
| `hejnal match` | Matches the saved inventory against the catalog. |
| `hejnal report fixlist\|overview\|evidence\|nis2\|monthly\|weekly` | Prints a report from the saved runs. |
| `hejnal systems [host]` | Lists the systems seen, or prints the history of one: versions, items found and fixed, and when it went away. |
| `hejnal accept` | Accepts an item you checked, lists what is accepted or removes an acceptance. |
| `hejnal issues` | Keeps a GitHub issue for every item to fix: opens, closes and reopens issues as the runs find and stop finding items. |
| `hejnal leaks scan\|breaches` | Finds secrets in source code, and accounts in known data breaches. |
| `hejnal code scan` | Checks dependencies, secrets, infrastructure code and container images, for CI. |
| `hejnal serve` | Serves the results over a REST API. |
| `hejnal mcp` | Serves the results to AI assistants over MCP; with `-code`, lets a coding assistant check its own fix. |
| `hejnal rules` | Lists the products Hejnal recognises. |

Run `hejnal <command> -h` for flags. Useful ones: `-lang en|pl`, `-checks`,
`-no-ct` to skip certificate transparency, `-no-epss`, `-no-nvd`, `-no-euvd`,
`-no-eol`, `-offline`, `-kev-file`, `-euvd-file`, `-concurrency` and `-timeout`.

### Files

Everything lives in the state directory (`.hejnal` by default, `-state` to
change it):

| File | Contents |
|---|---|
| `inventory.json` | Hosts, open services, certificates and recognised products. |
| `findings.json` | Findings from the last run. |
| `reported.json` | The findings people were last told about, used to tell what is new. |
| `weekly.json` | When the last weekly summary was sent. |
| `accepted.json` | Items accepted with `hejnal accept`: which findings, why, by whom and until when. |
| `systems.json` | Every service that answered: how its host was found, what runs there, when it was first and last seen, the versions it showed, and when it went away and came back. Gone ones are kept for 400 days. |
| `system-changes.json` | New, gone and updated services people have not been told about yet. |
| `history/` | Findings from earlier runs; the last 400 are kept, over a year of daily runs. |
| `fixlist.md` | The fix list from the last `hejnal run`. |
| `leaks.json`, `breaches.json` | Saved secret scans (secrets partly hidden) and breach counts, included in the next run. |
| `leaks.key` | The private key for secret fingerprints. |
| `cache/kev.json`, `cache/euvd-kev.json`, `cache/euvd/`, `cache/epss.json`, `cache/nvd/`, `cache/eol.json` | Downloaded feeds. KEV is refreshed after 6 hours, ENISA's list once a day after ENISA publishes it at 07:00 UTC, EUVD records and NVD records after a week (NVD's after a day while NVD has not analysed a flaw yet), EPSS scores when they are more than two days old, and endoflife.date's support dates after a day, only when a product shows a version they cover. |

### Offline and air-gapped use

Download the feeds on a connected machine with `hejnal feeds`. Copy
`.hejnal/cache/kev.json`, `.hejnal/cache/euvd-kev.json` and
`.hejnal/cache/eol.json` across, then run with `-offline` (or point
`-kev-file` and `-euvd-file` at the copies; the support dates are then read
from the cache). Discovery still needs network access to your own
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
hejnal code scan -sbom shop.cdx.json .               # and a bill of materials
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
`-item 3f9a1c0d` says only whether that one item is still found, with the
exit statuses of [`hejnal live -item`](#right-after-a-deploy); run it with
the `-project` name and the options of the scan that found the item.
`-save` keeps the result in the
state directory, so the daily fix list and alerts include it, scored again
each day: a dependency flaw that joins CISA's list tomorrow becomes urgent
tomorrow. `-upload <address>` sends the results, never the code, to Hejnal
Cloud with the token in `HEJNAL_UPLOAD_TOKEN`.

**Bill of materials.** `-sbom shop.cdx.json` also writes the packages found
as a software bill of materials (SBOM) in [CycloneDX](https://cyclonedx.org)
1.6 JSON, which tools such as Dependency-Track import. It lists every
package once, whether an advisory covers it or not, with its version, its
[package URL](https://github.com/package-url/purl-spec) and the files that
name it; the packages of images given with `-image` are in the same list.
Packages only development or tests use have the scope `excluded`. The list
holds what lockfiles and package databases record, so it has no dependency
graph, licences or hashes. It has no advisories either: those change daily,
and the fix list and SARIF carry them. Kept with each release, the file
records what the release shipped with.

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
      - uses: Legatia/hejnal@v0.7.1
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
against the release's checksums, and runs it on the runner. In releases
after 0.7.1, `sbom: hejnal.cdx.json` also writes the bill of materials; the
`sbom` output is its path, for a step such as `actions/upload-artifact`.

In releases after 0.7.1, the action can also check the deployed system
[right after a deploy](#right-after-a-deploy). Give it the address in `url`
(one per line for several) in a job that runs once the deploy is done:

```yaml
  deploy:
    needs: scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7        # for scope.json
      # ... your deploy steps ...
      - uses: Legatia/hejnal@<release>
        with:
          url: https://app.your-domain.pl
          code-scan: "false"             # the code was scanned before the deploy
          # scope: scope.json
          # wait: 2m
          # fail-on: high
```

The step waits up to `wait` for the system to answer, writes what it found
to the job summary, and fails when an item reaches `fail-on` or nothing
answers. The scope file has to be in the checkout and list the address. In a
public repository the job log and summary are public, and they name what
was found.

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
| `GET /v1/changes` | What is new and what was resolved since the last notification, and which services are new, gone or updated. |
| `GET /v1/systems`, `GET /v1/systems/{host}` | The systems seen with the items found on each, and the history of one system. Parameter for one system: `lang`. |
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
severity, host or CVE, the inventory, the history of a system and a NIS2
draft. These tools only read.
With `-allow-runs -scope scope.json`, it can also start a scan.

### Fixing with a coding assistant

A coding assistant can take an item, make the change and ask Hejnal whether
the item is still found, so it stops when Hejnal no longer finds the item,
not when it believes the fix worked. Name the source directory with `-code`:

```json
{
  "mcpServers": {
    "hejnal": {
      "command": "hejnal",
      "args": ["mcp", "-code", "/home/anna/src/shop", "-allow-runs", "-scope", "/srv/hejnal/scope.json"]
    }
  }
}
```

| Tool | Offered with | What it does |
|---|---|---|
| `hejnal_code_scan` | `-code <directory>` | Checks the directory as it is now: dependencies, secrets and infrastructure code, without container images or the Git history. Each item comes with its ID, what to do, the files and lines, and for a dependency the version that fixes it. |
| `hejnal_live_check` | `-allow-runs` | Looks at one system in the scope, as [`hejnal live`](#right-after-a-deploy) does: the front page, the certificate and the fixed paths. An address outside the scope is refused. `wait_seconds` gives a deploy up to five minutes to come up. |

Both take `item`, the ID of one item, and then answer with one status:

| Status | Meaning |
|---|---|
| `gone` | The item was found before, in a saved result or earlier in the session, and is not found now. Only this status means fixed. |
| `found` | The item is still there. |
| `moved` | Not fixed: the same problem now has another ID, such as after an update to a version that still has the flaw. The answer carries the new item. |
| `not_found` | Hejnal has no record that the item was ever found here, so it cannot say it was fixed. |
| `unknown` | This check cannot tell, and says why: the item belongs to another project or system, or to a kind this check does not cover. |

Both checks save nothing but the downloaded feeds, so the fix list, the
alerts and each system's history change only with the next `hejnal run` or
`hejnal code scan -save`. As with `hejnal code scan`, package names and
versions go to OSV and nothing else leaves the machine, so `-code` is
refused together with `-offline`. `-project` and `-exclude` work as they do
for `hejnal code scan`.

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
- **Systems on record:** every system that answered in the period, when it
  was first and last seen, whether it still answers, and how many items
  were found on it and fixed.
- **Controls it supports**, for auditors: SOC 2 CC7.1 and CC4.1, ISO/IEC
  27001:2022 A.8.8 and A.5.7, and NIS2 Article 21(2)(e), each with what in
  the report speaks to it. Whether a control is met stays the auditor's call.
- A SHA-256 fingerprint of the runs used, to check the report against them.

`-format json` writes the same evidence as data (schema
`https://github.com/Legatia/hejnal/evidence/v1`): the runs, every item's
exposure with its CVEs and dates, the accepted risks, the systems on record
and the controls, for compliance tools and audit workpapers.

It is not an audit or a certification, and it says so. Times to fix are
measured between runs, so they include the wait for the next run. An item
Hejnal reported without seeing a version, and later ruled out by the version
it saw, is listed as ruled out: it counts neither as found nor as fixed, here
and in the monthly report. `-since
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
a missing DMARC policy 50 and a watch-only one 40. A release past its end of
support scores 55, or 65 on a gateway, remote-access product, network device
or camera, and a release whose support ends within 90 days 30. The item
keeps its ID from the warning to the upgrade.

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
- Fix items as Jira issues, beside GitHub
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
from NVD, certificate transparency search from [crt.sh](https://crt.sh/),
end-of-support dates from [endoflife.date](https://endoflife.date) (MIT
License), and open-source advisories from [OSV](https://osv.dev), each under
the terms of the database it comes from (GitHub, PyPI, Go, RustSec, Debian,
Ubuntu, Alpine and others).
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
  WordPress, PHP, GitLab i Jenkins, a także narzędzia AI, które zespół może
  uruchomić sam: Ollama, Open WebUI, Flowise, Jupyter, Gradio, ComfyUI i
  Dify. Robi to jednym zwykłym zapytaniem
  `GET /` na usługę; strona na Next.js App Router dostaje jeszcze jedno, z
  nagłówkiem `RSC: 1`.
- **Porównuje** je z katalogiem CISA KEV i z listą wykorzystywanych podatności
  ENISA w europejskiej bazie EUVD. Pokazuje identyfikatory EUVD, podatności,
  które zna tylko ENISA, i to, kiedy ENISA wpisała podatność wcześniej niż
  CISA. Gdy produkt pokazuje wersję, sprawdza w NVD, czy ta wersja jest
  podatna. Z opcją `-checks` odczytuje też wersję produktów, które jej nie
  pokazują na stronie głównej, m.in. WordPressa, Grafany i Next.js.
- **Pilnuje końca wsparcia:** według endoflife.date wskazuje wersje, które
  nie dostają już poprawek bezpieczeństwa, i te, którym wsparcie kończy się w
  ciągu 90 dni, z datą oraz najbliższą i najnowszą wspieraną wersją. Lista
  poprawek kończy się nadchodzącymi terminami: końcem wsparcia, wygasaniem
  certyfikatów i końcem akceptacji.
- **Sprawdza kod w CI:** `hejnal code scan` porównuje zależności, obrazy
  kontenerów, kod infrastruktury i sekrety z tym, co atakujący wykorzystują,
  i zapisuje wynik także jako SARIF dla GitHub code scanning. Z `-sbom`
  zapisuje też listę pakietów jako SBOM w formacie CycloneDX 1.6.
- **Szuka wycieków:** sekretów w kodzie źródłowym (klucze API, tokeny, klucze
  prywatne) i kont z Twoich domen w znanych wyciekach danych (Have I Been
  Pwned).
- **Pisze** listę poprawek po polsku lub angielsku, wysyła powiadomienia na
  Slacka, Microsoft Teams lub e-mailem, przygotowuje raport miesięczny i
  projekt wczesnego ostrzeżenia NIS2 (zgłoszenie do właściwego CSIRT, zwykle
  przez system S46).
- **Udostępnia wyniki** przez REST API i serwer MCP dla asystentów AI.
- **Pozwala asystentowi programisty sprawdzić własną poprawkę:**
  `hejnal mcp -code katalog` udostępnia narzędzie `hejnal_code_scan`
  (zależności, sekrety i kod infrastruktury w tym katalogu), a opcja
  `-allow-runs` narzędzie `hejnal_live_check` (jeden system z zakresu, jak
  `hejnal live`, razem ze stałymi ścieżkami). Oba przyjmują identyfikator
  punktu w polu `item` i odpowiadają jednym stanem: `gone` (punkt był
  wykrywany i już nie jest; tylko ten stan oznacza naprawę), `found` (nadal
  jest), `moved` (ten sam problem ma nowy identyfikator, na przykład po
  aktualizacji do wersji, która nadal ma lukę), `not_found` (Hejnal nie ma
  zapisu, że punkt był tu kiedykolwiek wykryty) albo `unknown` (to
  sprawdzenie nie może tego stwierdzić i podaje powód). Sprawdzenia
  niczego nie zapisują poza pobranymi listami. Do OSV trafiają tylko nazwy i
  wersje pakietów, więc `-code` nie działa razem z `-offline`.
- **Sprawdza jeden punkt po naprawie:** `hejnal live -item 3f9a1c0d
  https://sklep.twoja-domena.pl` i `hejnal code scan -item 3f9a1c0d` mówią
  tylko, czy ten punkt jest nadal wykrywany: kod 2, dopóki jest, kod 0, gdy
  już nie jest, i kod 1, gdy to sprawdzenie nie może tego stwierdzić.
- **Śledzi zmiany w systemach:** każde uruchomienie mówi, które usługi
  odpowiadają pierwszy raz (z tym, co na nich działa, i skąd Hejnal je zna),
  które nie odpowiadają od dwóch sprawdzeń (z podpowiedzią, by usunąć rekord
  DNS wycofanego systemu) i które produkty mają nową wersję.
- **Prowadzi historię każdego systemu:** `hejnal systems` wypisuje systemy z
  rejestru, a `hejnal systems shop.example.com -lang pl` historię jednego:
  pierwszą odpowiedź, kolejne wersje, wykryte i naprawione pozycje oraz
  dzień, w którym zniknął. Lista wskazuje systemy, na których działają
  narzędzia AI. Raport dowodowy zawiera tabelę tych systemów.
- **Sprawdza system zaraz po wdrożeniu:** `hejnal live -wait 2m
  https://app.twoja-domena.pl` sprawdza jeden adres z pliku zakresu, bez
  czekania na codzienne uruchomienie: to, co odpowiada, certyfikat, stałe
  ścieżki z opcji `-checks` oraz podatności i koniec wsparcia rozpoznanych
  produktów. Łączy się tylko z tym adresem i z hostem z zakresu, do którego
  on przekierowuje. Niczego nie zapisuje poza pobranymi listami, więc
  historia codziennych sprawdzeń zostaje bez zmian. Kończy się kodem 2, gdy
  punkt osiąga poziom z opcji `-fail-on` (domyślnie `high`), a kodem 1, gdy
  nic nie odpowiada albo odpowiedzią jest błąd 5xx. W GitHub Actions służy
  do tego pole `url` akcji.
- **Pamięta sprawdzone punkty:** każdy punkt listy ma identyfikator. Polecenie
  `hejnal accept` zapisuje, kto sprawdził punkt, dlaczego i do kiedy.
  Powiadomienia i kod wyjścia pomijają go wtedy przez 90 dni albo do daty z
  opcji `-until`, najwyżej przez rok. Nowa podatność w tym samym punkcie i tak
  się pokaże.
- **Prowadzi zgłoszenia na GitHubie:** `hejnal issues -repo twoja-org/infra
  -lang pl` otwiera zgłoszenie dla każdego punktu listy poprawek, z
  priorytetem, szacowanym nakładem pracy i poleceniem do samodzielnego
  sprawdzenia, i przypisuje je właścicielowi systemu z pola `owners` w pliku
  zakresu. Zgłoszenie kończy się blokiem „Naprawa i sprawdzenie”: pakiet,
  zainstalowana i naprawiona wersja oraz pliki albo adres systemu i produkt,
  a także polecenie, które mówi, czy punkt jest nadal wykrywany, tak by
  mógł z niego skorzystać człowiek albo asystent programisty. Zamyka zgłoszenie, gdy kolejne sprawdzenie nie znajduje już
  punktu albo gdy punkt zaakceptowano, i otwiera je ponownie, gdy punkt
  wraca. Token pochodzi ze zmiennej `HEJNAL_GITHUB_TOKEN` lub `GITHUB_TOKEN`.
  Publicznego repozytorium Hejnal nie użyje bez opcji `-public`.

[Przykładowa lista poprawek](examples/fix-list.pl.md).

Hejnal sprawdza tylko systemy z pliku zakresu. Plik musi wskazywać, kto i kiedy
potwierdził zgodę na testy: `hejnal init` zapisuje to z opcji `-by`. Nie loguje się, nie zgaduje haseł ani ścieżek i
nie używa exploitów.

```sh
hejnal init -domain twoja-domena.pl -by "Imię i nazwisko, stanowisko"
hejnal run -checks -lang pl
hejnal report fixlist -lang pl
hejnal report monthly -lang pl
hejnal live -wait 2m -lang pl https://app.twoja-domena.pl
hejnal accept -item 3f9a1c0d -reason "Wersja 6.8.3 ma poprawkę" -by "Anna Nowak"
hejnal issues -repo twoja-org/infra -lang pl
hejnal leaks scan -history ~/kod/serwis
hejnal code scan -exclude testdata .
```

Sprawdzaj wyłącznie systemy, które należą do Ciebie, albo takie, na których
testowanie masz pisemną zgodę.
