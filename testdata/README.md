# Test data

- `kev_sample.json` holds 21 real entries from CISA's Known Exploited
  Vulnerabilities catalog, version 2026.11.03, copied unchanged from
  [cisagov/kev-data](https://github.com/cisagov/kev-data) (CC0 1.0). They were
  picked to test matching. Some should match, such as WordPress core, PHP,
  FortiOS and Fortinet "Multiple Products" entries that name FortiOS. Others
  must not match, such as WordPress plugins, PHPMailer, FortiMail and Fortinet
  "Multiple Products" entries that do not name FortiOS.

- `euvd_kev_sample.json` holds 29 real entries from ENISA's list of exploited
  vulnerabilities (`/api/kev/dump`) of 2026-11-07, copied unchanged: the
  entries for the CISA sample above, six flaws only ENISA lists (among them
  MikroTik RouterOS, FortiWeb spelled "Fortiweb" and Zbtlink "Various"), and
  two edge cases: CVE-2023-3519, which both list but the CISA sample leaves
  out, and CVE-2026-69836, which ENISA's data marks as CISA's although CISA's
  catalog no longer has it.
- `euvd_record_EUVD-2026-72024.json` is the real EUVD record
  (`/api/enisaid`) of the MikroTik flaw, as returned on 2026-11-07.

Source: ENISA European Vulnerability Database (EUVD),
<https://euvd.enisa.europa.eu>, reused under ENISA's legal notice, which
allows reproduction with acknowledgement of the source.

EPSS responses in the tests are written inline with made-up scores. They test
the API format only and are not real EPSS data.
