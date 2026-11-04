# Test data

- `kev_sample.json` holds 21 real entries from CISA's Known Exploited
  Vulnerabilities catalog, version 2026.11.03, copied unchanged from
  [cisagov/kev-data](https://github.com/cisagov/kev-data) (CC0 1.0). They were
  picked to test matching. Some should match, such as WordPress core, PHP,
  FortiOS and Fortinet "Multiple Products" entries that name FortiOS. Others
  must not match, such as WordPress plugins, PHPMailer, FortiMail and Fortinet
  "Multiple Products" entries that do not name FortiOS.

EPSS responses in the tests are written inline with made-up scores. They test
the API format only and are not real EPSS data.
