# HTTP Outcome Taxonomy (Week 4, W4.3)

Specifies the outcome classes the Week 6 retrievability checker
(`src/http_retrievability.py`, not yet built) assigns to every advisory and
firmware-download reference URL. This is the classification layer that feeds
Dimension 3 (fix obtainability) in `docs/scoring_rubric_v0.1.md`, and it
implements decisions D4 and D5.

## Outcome classes

| Class | Definition | Dimension-3 contribution |
|---|---|---|
| **live_200** | Final URL (after redirects) returns HTTP 200 and the response body is not a soft-404 (see heuristic below) | Counts as reachable |
| **hard_404** | HTTP 404, 410, or another explicit not-found status | Counts as unreachable |
| **soft_404** | HTTP 200, but the response body matches the soft-404 content heuristic (below) | Counts as unreachable |
| **redirect_to_root** | Final URL, after following redirects, lands on the site's root/home page rather than the original path -- a common vendor pattern for a retired advisory ("we can't find that page, here's our homepage") | Counts as unreachable |
| **auth_or_paywall_gated** | HTTP 401/403 with a login/support-contract page, or a redirect to a login endpoint | Counts as Dimension-3 score 1 (advisory acknowledged to exist but not obtainable by an ordinary defender), per D5 |
| **waf_challenge** | HTTP 403/429, or a 200 whose body is a bot-detection/CAPTCHA challenge page (Cloudflare, Akamai, etc.), distinguished from a real 403 by matching known WAF challenge-page signatures | Logged as a **distinct outcome class**, per PR1's retrievability ground rules ("vendors whose infrastructure blocks automated retrieval are recorded as a distinct outcome class rather than silently scored as failures") -- not automatically scored 0, flagged for the Limitations section instead |
| **dns_failure** | DNS resolution fails for the URL's host | Counts as unreachable |
| **tls_failure** | TLS handshake fails (expired/invalid certificate, protocol mismatch) | Counts as unreachable |
| **timeout** | No response within the crawler's timeout after retries | Logged as a distinct outcome, treated as unreachable but flagged (transient-network false negatives are what the Week 8 second crawl pass and its flip-rate finding are for) |

## Soft-404 content heuristic

A `live_200` response is reclassified as `soft_404` when the response body,
after stripping HTML tags, matches any of:

- A generic not-found phrase (`page not found`, `content no longer available`,
  `this page has moved`, `article not found`, `the page you requested`) near
  the top of the body (first ~2000 characters), OR
- The response is under a threshold byte count (< 512 bytes of extracted
  text) AND contains no reference to the CVE ID, product name, or any
  version string from the record's own affected-version data -- a real
  advisory page for this CVE should mention at least one of these; a generic
  landing page will not, OR
- The final URL's path is the site's bare root (`/`) or a generic
  `/support`, `/downloads` index page with no path segment matching anything
  in the original URL's path.

This mirrors PR1's existing rule: "counting redirects to generic landing
pages as failures rather than successes."

## D4 -- archive-recoverable advisories

Obtainability (Dimension 3) is scored on **live vendor infrastructure only**.
A dead advisory that is recoverable via the Wayback Machine / Memento
aggregator does not score as obtainable -- a defender who follows the link
in a scanner report gets a 404, not an archive. Archive availability is
recorded as a **separate field** (`archive_available: bool`,
`archive_last_seen_live: date | None`), used for:

- Separating "never existed" (the URL never appears in Wayback either) from
  "existed and died" (Wayback has a snapshot, current live check fails).
- Dating the death for the RQ2 retrievability decay curve (Week 7).

## D5 -- advisory live, firmware artifact gone

Resolved on the 0/1/2 scale already in the rubric:

- **2**: advisory live AND (if it names a specific firmware file) that file's
  URL is also live.
- **1**: advisory live, but the named firmware file is unreachable, or is
  gated behind a login/support-contract wall (`auth_or_paywall_gated`).
- **0**: advisory itself is unreachable.

Constraint carried over from PR1: the crawler downloads no firmware
binaries. Every obtainability check is a reachability check (HEAD request or
a GET with the body discarded after a status/size check), never a download.
