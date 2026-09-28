# Positive-Control Set (Evaluation 1)

Built 2026-09-28T03:36:37+00:00. 40 controls: 19 run against the current code now, 21 HTTP controls waiting on the Week 7 retrievability checker.

**Current code: 19 of 19 membership and scoring controls pass.**

## Membership and scoring controls

| Group | ID | Dimension | Expected | Actual | Pass | Note |
|---|---|---|---|---|---|---|
| membership | CVE-2024-0531 |  | True | True | yes | Tenda A15 router, stack overflow in web management UI |
| membership | CVE-2025-27480 |  | False | False | yes | Microsoft Remote Desktop Gateway Service, Windows server software |
| membership | CVE-2024-38015 |  | False | False | yes | Microsoft RD Gateway denial of service |
| membership | CVE-2025-21403 |  | False | False | yes | Microsoft On-Premises Data Gateway |
| membership | CVE-2024-22316 |  | False | False | yes | IBM Sterling File Gateway, enterprise software |
| membership | CVE-2024-45655 |  | False | False | yes | IBM Application Gateway |
| membership | CVE-2024-22457 |  | False | False | yes | Dell Secure Connect Gateway, enterprise software |
| membership | CVE-2024-44100 |  | False | False | yes | Google Pixel modem component, mobile handset |
| membership | CVE-2024-27795 |  | False | False | yes | Apple macOS camera extension |
| scoring_nvd | CVE-1999-0453 | identifiability | 0 | 0 | yes | rubric worked example: wildcard-only CPE |
| scoring_nvd | CVE-2012-0695 | identifiability | 1 | 1 | yes | rubric worked example: upper bound only (replaced CVE-2009-5037, which also lists exact versions) |
| scoring_nvd | CVE-2009-5037 | identifiability | 2 | 2 | yes | range plus dozens of exact versions; exact version scores 2 per rubric |
| scoring_nvd | CVE-2026-13050 | identifiability | 2 | 2 | yes | rubric worked example: fully bounded ranges |
| scoring_nvd | CVE-2002-1595 | fix_availability | 2 | 2 | yes | rubric worked example: Patch-tagged reference |
| scoring_nvd | CVE-1999-0453 | fix_availability | 0 | 0 | yes | rubric worked example: no Patch/Vendor Advisory tag, no fix language |
| scoring_v5 | CVE-2024-0531 | identifiability | 1 | 1 | yes | rubric worked example: one affected version, no range |
| scoring_v5 | synthetic-fa0 | fix_availability | 0 | 0 | yes | exploit reference only; must score 0 (the C2 bug scored this 1) |
| scoring_v5 | synthetic-fa1 | fix_availability | 1 | 1 | yes | vendor-advisory reference, no fixed version |
| scoring_v5 | synthetic-fa2 | fix_availability | 2 | 2 | yes | patch-tagged reference |

## HTTP outcome controls

Observed values are what each URL returned when this set was built. The checker passes a control when it assigns the expected class.

| URL | Expected class | Observed at build | Note |
|---|---|---|---|
| https://www.cisa.gov/known-exploited-vulnerabilities-catalog | live_200 | 200, 284790 bytes | stable government page |
| https://nvd.nist.gov/developers/vulnerabilities | live_200 | 200, 2092 bytes | stable government page |
| https://github.com/CVEProject/cvelistV5 | live_200 | 200, 292881 bytes | stable repository page |
| https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/costin | live_200 | 200, 55212 bytes | stable conference page |
| https://httpbin.org/status/200 | live_200 | 200, 0 bytes | test endpoint |
| https://httpbin.org/status/404 | hard_404 | 404, 0 bytes | test endpoint |
| https://httpbin.org/status/410 | hard_404 | 410, 0 bytes | test endpoint |
| https://www.netgear.com/support/pa-gap-nonexistent-7731/ | hard_404 | 404, 39641 bytes | real vendor, missing page returns 404 |
| https://www.tp-link.com/us/support/pa-gap-nonexistent-7731/ | hard_404 | 404, 1867 bytes | real vendor, missing page returns 404 |
| https://old.tenda.com.cn/error?path=/pa-gap-nonexistent-7731 | hard_404 | 404, 153 bytes | real vendor, reached via two 302s, ends at 404 |
| https://www.hikvision.com/en/pa-gap-nonexistent-7731/ | soft_404 | 200, 29184 bytes | real vendor, missing page returns 200 |
| https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2F | redirect_to_root | 200 via 302, 9593 bytes | test endpoint, redirects to site root |
| https://httpbin.org/status/401 | auth_or_paywall_gated | 401, 0 bytes | test endpoint |
| https://httpbin.org/basic-auth/user/pass | auth_or_paywall_gated | 401, 0 bytes | test endpoint, basic-auth challenge |
| https://httpbin.org/status/429 | waf_challenge | 429, 0 bytes | test endpoint, rate-limit status |
| https://httpbin.org/status/403 | waf_challenge | 403, 0 bytes | test endpoint; a bare 403 with no login page, classed as blocked |
| https://pa-gap-control.invalid/advisory | dns_failure | DNS failure | RFC 2606 reserved TLD, never resolves |
| https://expired.badssl.com/ | tls_failure | TLS error | test endpoint, expired certificate |
| https://self-signed.badssl.com/ | tls_failure | TLS error | test endpoint, self-signed certificate |
| https://wrong.host.badssl.com/ | tls_failure | TLS error | test endpoint, hostname mismatch |
| http://10.255.255.1/ | timeout | connect timeout | non-routable address, connection never completes |
