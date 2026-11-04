<!-- Example output of `hejnal run` against test services that mimic a FortiGate VPN, WordPress on PHP and Jenkins, matched against the real CISA KEV catalog 2026.11.03. Host names were changed to example.com. -->

# Hejnal fix list: Example Sp. z o.o.

Generated 2026-11-04 12:42 UTC · Hosts: 3 · Services: 3 · Products recognised: 4

Sources: CISA Known Exploited Vulnerabilities catalog 2026.11.03.

**Fix now: 3 · This week: 0 · This month: 2 · Later: 0**

## Fix now (critical)

### 1. Fortinet FortiGate SSL VPN on vpn.example.com:443

- **Why:** Known exploited flaws in this product: 21. The newest was added to CISA's catalog on 2026-10-16.
- **What to do:** Find the installed version, compare it with the vendor advisories below and update to a fixed release. If no fix exists, follow the vendor's mitigation or take the service off the internet.
- **Check for compromise:** CISA asks for forensic triage for at least one of these flaws. Updating is not enough if the system was exposed before the fix: look for signs of compromise, such as unknown accounts, files or connections.
- **Seen at:** `https://vpn.example.com/remote/login?lang=en` (`path /remote/login`) · version not shown
- **Flaws:**
  - **CVE-2025-61624**: Fortinet Multiple Products Path Traversal Vulnerability · added 2026-10-16 · forensic triage
  - **CVE-2025-25249**: Fortinet Multiple Products Heap-based Buffer Overflow Vulnerability · added 2026-09-09 · forensic triage
  - **CVE-2025-68686**: Fortinet FortiOS Exposure of Sensitive Information to an Unauthorized Actor Vulnerability · added 2026-07-27
  - **CVE-2026-24858**: Fortinet Multiple Products Authentication Bypass Using an Alternate Path or Channel Vulnerability · added 2026-01-27
  - **CVE-2025-59718**: Fortinet Multiple Products Improper Verification of Cryptographic Signature Vulnerability · added 2025-12-16
  - …and 16 more (full list in findings.json)
- **Advisories:** <https://fortiguard.fortinet.com/psirt/FG-IR-26-122> · <https://nvd.nist.gov/vuln/detail/CVE-2025-61624> · <https://fortiguard.fortinet.com/psirt/FG-IR-25-084> · <https://nvd.nist.gov/vuln/detail/CVE-2025-25249>

> Hejnal recognised the product but did not verify its version, so it may already be patched. Close this item once you have confirmed the installed version includes the fix.

### 2. WordPress on www.example.com:443

- **Why:** Known exploited flaws in this product: 4. The newest was added to CISA's catalog on 2026-11-03.
- **What to do:** Find the installed version, compare it with the vendor advisories below and update to a fixed release. If no fix exists, follow the vendor's mitigation or take the service off the internet.
- **Check for compromise:** CISA asks for forensic triage for at least one of these flaws. Updating is not enough if the system was exposed before the fix: look for signs of compromise, such as unknown accounts, files or connections.
- **Seen at:** `https://www.example.com/` (`generator WordPress 6.8.1`) · version `6.8.1`
- **Flaws:**
  - **CVE-2026-119977**: WordPress WordPress Core Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability · added 2026-11-03 · forensic triage
  - **CVE-2026-87902**: WordPress Core Remote File Inclusion Vulnerability · added 2026-09-25 · forensic triage
  - **CVE-2026-63030**: WordPress Core Interpretation Conflict Vulnerability · added 2026-07-21 · forensic triage
  - **CVE-2026-60137**: WordPress Core SQL Injection Vulnerability · added 2026-07-21
- **Advisories:** <https://wordpress.org/news/2026/10/wordpress-7-1-4> · <https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-470-713-unauthenticated-upgrade-window-staged-installer-remote-code-execution> · <https://nvd.nist.gov/vuln/detail/CVE-2026-119977> · <https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp>

> Hejnal recognised the product but did not verify its version, so it may already be patched. Close this item once you have confirmed the installed version includes the fix.

### 3. PHP on www.example.com:443

- **Why:** Known exploited flaws in this product: 5. The newest was added to CISA's catalog on 2026-10-26.
- **What to do:** Find the installed version, compare it with the vendor advisories below and update to a fixed release. If no fix exists, follow the vendor's mitigation or take the service off the internet.
- **Check for compromise:** CISA asks for forensic triage for at least one of these flaws. Updating is not enough if the system was exposed before the fix: look for signs of compromise, such as unknown accounts, files or connections.
- **Seen at:** `https://www.example.com/` (`header X-Powered-By: PHP/8.3.12`) · version `8.3.12`
- **Flaws:**
  - **CVE-2026-109618**: PHP Memory Corruption Vulnerability · added 2026-10-26 · forensic triage
  - **CVE-2026-109619**: PHP Stale Internal Request-State Vulnerability · added 2026-10-26 · forensic triage
  - **CVE-2024-4577**: PHP-CGI OS Command Injection Vulnerability · added 2024-06-12 · used in ransomware campaigns
  - **CVE-2019-11043**: PHP FastCGI Process Manager (FPM) Buffer Overflow Vulnerability · added 2022-03-25 · used in ransomware campaigns
  - **CVE-2012-1823**: PHP-CGI Query String Parameter Vulnerability · added 2022-03-25
- **Advisories:** <https://www.php.net/> · <https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching> · <https://nvd.nist.gov/vuln/detail/CVE-2026-109618> · <https://nvd.nist.gov/vuln/detail/CVE-2026-109619>

> Hejnal recognised the product but did not verify its version, so it may already be patched. Close this item once you have confirmed the installed version includes the fix.

## This month (medium)

### 4. Jenkins admin interface reachable on ci.example.com:443

- **Why:** Hejnal reached this admin interface from where it ran. Exposed admin panels are a common way in for attackers.
- **What to do:** If it is reachable from the internet, move it behind a VPN or an IP allow-list and require multi-factor sign-in.
- **Seen at:** `https://ci.example.com/` (`header X-Jenkins: 2.462.3`)

### 5. Jenkins on ci.example.com:443

- **Why:** Known exploited flaws in this product: 6. The newest was added to CISA's catalog on 2025-10-02.
- **What to do:** Find the installed version, compare it with the vendor advisories below and update to a fixed release. If no fix exists, follow the vendor's mitigation or take the service off the internet.
- **Seen at:** `https://ci.example.com/` (`header X-Jenkins: 2.462.3`) · version `2.462.3`
- **Flaws:**
  - **CVE-2024-23897**: Jenkins Command Line Interface (CLI) Path Traversal Vulnerability · added 2024-08-19 · used in ransomware campaigns
  - **CVE-2017-1000353**: Jenkins Remote Code Execution Vulnerability · added 2025-10-02
  - **CVE-2015-5317**: Jenkins User Interface (UI) Information Disclosure Vulnerability · added 2023-05-12
  - **CVE-2019-1003029**: Jenkins Script Security Plugin Sandbox Bypass Vulnerability · added 2022-04-25
  - **CVE-2019-1003030**: Jenkins Matrix Project Plugin Remote Code Execution Vulnerability · added 2022-03-25
  - …and 1 more (full list in findings.json)
- **Advisories:** <https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314> · <https://nvd.nist.gov/vuln/detail/CVE-2024-23897> · <https://www.jenkins.io/security/advisory/2017-04-26/> · <https://nvd.nist.gov/vuln/detail/CVE-2017-1000353>

> Hejnal recognised the product but did not verify its version, so it may already be patched. Close this item once you have confirmed the installed version includes the fix.

---

Hejnal only looks at what any visitor can see: one ordinary request per web service. It never logs in or tries exploits, so it can miss flaws and it does not confirm versions. Data: CISA Known Exploited Vulnerabilities catalog (CC0) and FIRST EPSS.
