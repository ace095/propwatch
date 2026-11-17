# Website Audit: owasp.org (Nonprofit)

## Executive Summary

This audit combines passive security, privacy, and accessibility reviews of owasp.org. The site has a strong header posture (HSTS with preload, a detailed CSP, clickjacking and MIME-sniffing protections, restrictive Referrer-Policy and Permissions-Policy). It also shows no analytics, which is a privacy positive. Three confirmed Medium-severity issues stand out: the CSP allows `'unsafe-inline'` for scripts, no privacy policy page was detected, and 3 of 8 images lack alt text. Several Low items cover technology disclosure, cookie and consent clarity, third-party embeds, and sensitive-sounding paths in robots.txt. Three checks could not be completed because of DNS failures in the scanning environment: TLS certificate validity, the HTTP-to-HTTPS redirect, and SPF/DMARC email authentication. These are open questions, not confirmed problems, and should be re-run. All findings are passive and are not the result of penetration testing or a full WCAG audit.

---

## Security

### Transport & Infrastructure Security: owasp.org (nonprofit)

**Summary:** The passive findings show a strong header posture: HSTS with preload, a detailed CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy are all present, and nothing is listed as missing. Three checks (TLS certificate, HTTP-to-HTTPS redirect, SPF/DMARC) could not be completed, so they are open questions, not confirmed problems.

#### Issues and gaps

**1. CSP allows `'unsafe-inline'` for scripts: Medium**
- **What it means:** `script-src 'self' 'unsafe-inline'` weakens the CSP's main purpose. If an attacker injects markup into a page, inline scripts would not be blocked. `style-src` also allows `'unsafe-inline'`, which carries lower risk.
- **Standard:** PCI-DSS 6.4 / 11.6 (script and payment-page integrity, if donations or payments are handled), general XSS-prevention guidance, and state breach-law "reasonable security" expectations.
- **Fix:** Move to nonce- or hash-based `script-src` (Next.js supports nonces via middleware) and remove `'unsafe-inline'`. Keep the existing `report-uri` to monitor for breakage during the change.

**2. TLS certificate not verified: not rated (unknown)**
- **What it means:** The TLS probe failed with `Name or service not known`, a DNS resolution error. That indicates a problem in the scanning environment's lookup, not a certificate fault. The header fetch did return HTTP 200 with HSTS, which suggests the site is reachable over HTTPS. There is no evidence of an expired or invalid certificate, but validity, chain, expiry date and protocol versions were not checked.
- **Standard:** PCI-DSS 4.2.1 (strong cryptography in transit), state breach laws.
- **Fix:** Re-run the TLS check from a network with working DNS. Make sure certificate auto-renewal is monitored (Vercel normally manages this).

**3. HTTP-to-HTTPS redirect not verified: not rated (unknown)**
- **What it means:** The fetch of `http://owasp.org/` failed on DNS resolution, so `redirects_to_https` is null. The HSTS header (1 year, includeSubDomains, preload) and `upgrade-insecure-requests` suggest HTTPS is enforced, but the plain-HTTP redirect itself was not observed.
- **Standard:** PCI-DSS 4.2.1, FERPA/state-law data-in-transit expectations.
- **Fix:** Re-test, and confirm that `http://` returns a 301/308 to `https://` on the first hop.

**4. SPF and DMARC status unknown: not rated (unknown)**
- **What it means:** The DNS lookup failed, so email-spoofing protection was not checked. If DMARC is absent, that would be High, because the domain could be spoofed in phishing aimed at donors or members. If SPF is absent, that would be Medium. Neither can be confirmed or ruled out from this data.
- **Standard:** General anti-phishing practice. State breach laws are relevant if spoofing leads to credential or data loss.
- **Fix:** Run `dig TXT owasp.org` and `dig TXT _dmarc.owasp.org`. Publish an SPF record, and a DMARC policy moving from `p=none` to `quarantine` or `reject` with reporting enabled.

**5. Technology disclosure via `X-Powered-By: Next.js` and `Server: Vercel`: Low**
- **What it means:** This reveals the framework and host, which helps attackers target known issues. It is minor, and the Server header is largely unavoidable on Vercel.
- **Standard:** General hardening guidance (not a specific compliance control).
- **Fix:** Set `poweredByHeader: false` in `next.config.js`.

**6. robots.txt lists sensitive-sounding paths: Low (informational)**
- **What it means:** The file lists `/admin`, `/auth`, `/dashboard`, `/dev`, `/api/` and `/search`. This is not a vulnerability in itself, but it points to where admin and development areas may sit. These paths were not tested.
- **Standard:** General hardening guidance.
- **Fix:** Make sure those paths are protected by authentication and access controls, not by robots.txt. Consider restricting `/dev` to internal networks.

#### Positives
- HSTS is set with a 1-year max-age, includeSubDomains and preload.
- The CSP includes `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'` and reporting.
- Clickjacking and MIME-sniffing protections are in place (`X-Frame-Options: DENY`, `nosniff`).
- Referrer-Policy and Permissions-Policy are restrictive.

---

## Privacy

### Privacy & Data-Handling Assessment: owasp.org (Nonprofit)

These are passive findings only. They indicate how the site is configured from the outside and are not the result of penetration testing.

#### Issue 1: No privacy policy page detected
- **Severity:** Medium
- **Explanation:** The passive scan found no privacy policy page (`policy_pages_found` is empty). The site does mention cookies, so some cookie-related content may exist. Without a discoverable privacy policy, visitors cannot easily learn what personal data is collected, why, or how to exercise their rights. The scan may simply have missed a policy at a non-standard URL, so this should be verified manually. It also found no accessibility policy page.
- **Standard:** CCPA/CPRA (notice at collection) and GDPR (Articles 12–14, transparency), if the site serves California or EU/UK visitors. A nonprofit may be exempt from some CCPA thresholds but not from GDPR.
- **Fix:** Publish a plain-language privacy policy at a predictable URL such as `/privacy`, and link it from the site footer and any forms. It should cover data collected (including account sign-in and any data processed via the Supabase backend referenced in the CSP), purposes, retention, third-party processors, and contact details for data requests. Consider adding an accessibility statement as well.

#### Issue 2: Cookie mention without a detected consent mechanism
- **Severity:** Low
- **Explanation:** The site mentions cookies, but no cookie banner hint was detected. No analytics was detected either (`has_analytics: false`), which is a positive sign: there is no evidence of third-party tracking loaded before consent. If the site sets only strictly necessary cookies, a banner may not be required. If non-essential cookies or embeds are added later, consent would be needed.
- **Standard:** GDPR/ePrivacy (consent for non-essential cookies) and CCPA (opt-out of sale/sharing).
- **Fix:** Confirm which cookies are actually set. If they are all essential, state that in the privacy policy. If any non-essential cookies or trackers are introduced, add a consent mechanism before they load.

#### Issue 3: Third-party embeds may transmit visitor data
- **Severity:** Low
- **Explanation:** The CSP permits embedding content from YouTube, Vimeo, and Google Calendar, and loading images from Unsplash, YouTube, and Google domains. Visitors' IP addresses and browser details can reach these providers when such content loads. The CSP lists `youtube-nocookie.com`, which suggests privacy-enhanced embeds may be in use, but this was not confirmed.
- **Standard:** GDPR (third-party processors and transfers) and CCPA (disclosure of third-party sharing).
- **Fix:** Use privacy-enhanced embed modes (e.g. `youtube-nocookie.com`) consistently, consider click-to-load placeholders for video, and disclose these third parties in the privacy policy.

#### Positive findings
- **Referrer policy:** `strict-origin-when-cross-origin` is a sound setting. It limits URL leakage to other sites, so there is no concern here.
- **No analytics detected:** no evidence of analytics scripts that would trigger consent requirements.
- **Permissions-Policy:** camera, microphone, and geolocation are disabled, and `interest-cohort=()` opts out of FLoC-style tracking.
- **Transport and header hardening:** HSTS (with preload), a restrictive CSP, `X-Frame-Options: DENY`, and `nosniff` are all present, and no security headers were reported missing. These reduce the risk of data exposure.

#### Not assessed
- **Email authentication (SPF/DMARC):** not checked, because the DNS lookup failed. Its status is unknown and should be verified separately, as it affects spoofing of communications to members and donors.
- **HTTPS redirect:** not determined (`redirects_to_https: null`), though the HSTS header indicates HTTPS is enforced.

#### Summary
The main privacy gap is the apparent absence of a discoverable privacy policy. The rest of the privacy posture looks strong: no analytics, a protective referrer policy, and restrictive browser permissions. Verify the policy page manually, then document third-party embeds and cookie usage.

---

## Accessibility

### Accessibility Assessment: owasp.org (Passive Signals Only)

This review is based on a passive HTML parse (BeautifulSoup) of the page. It indicates likely problems but is not a full WCAG audit.

#### Issue 1: Images missing alt text
- **Severity:** Medium
- **What we found:** 3 of the 8 images (about 38%) have no alt attribute.
- **Why it matters:** Screen reader users get no description of these images. Depending on what they show, such as logos, charts, calls to action, or linked images, they may miss information or be unable to tell where a link goes. For a nonprofit, this can also shut out donors, members, and volunteers who use assistive technology.
- **Standard:** WCAG 2.1 AA, Success Criterion 1.1.1 (Non-text Content, Level A). This is also relevant to ADA exposure.
- **Fix:**
  - Give each informative image a short, meaningful `alt` description.
  - Give purely decorative images an empty `alt=""` so screen readers skip them.
  - If an image is the only content of a link or button, make the alt text describe the destination or action.
  - Add a template or CI check so new images can't be published without alt text.

#### Items with no issue detected
- **Language attribute:** Present. This suggests the page declares its language for screen readers (SC 3.1.1).
- **Page title:** Present. This suggests the page has a title for orientation and navigation (SC 2.4.2).

#### Important caveat
These checks cover only a small slice of WCAG 2.1 AA. They say nothing about color contrast, keyboard navigation, focus order, form labels, ARIA usage, heading structure, link purpose, or dynamically loaded content. The passing results above do not show the site is accessible. Run a full audit with axe-core or Pa11y, plus manual testing with a keyboard and a screen reader, to get a reliable picture.

---

## Top 5 Fixes (Ordered by Severity)

No High-severity issue was confirmed. The three confirmed Medium findings come first, followed by the unverified checks and then the highest-ranked Low item.

1. **Remove `'unsafe-inline'` from the CSP `script-src` (Medium, Security).** Move to nonce- or hash-based scripts, using Next.js middleware for nonces, and keep `report-uri` active to catch breakage.
2. **Publish a discoverable privacy policy (Medium, Privacy).** Verify manually first, since the scan may have missed a non-standard URL. Then publish at `/privacy`, link it from the footer and forms, and cover data collected, purposes, retention, third-party processors, and contact details.
3. **Add alt text to the 3 of 8 images missing it (Medium, Accessibility).** Use meaningful alt text for informative images and `alt=""` for decorative ones, then add a CI or template check. Follow with a full axe-core/Pa11y audit and manual keyboard and screen-reader testing.
4. **Re-run the incomplete checks, starting with SPF/DMARC (Unrated, Security).** Run `dig TXT owasp.org` and `dig TXT _dmarc.owasp.org` from a network with working DNS. A missing DMARC record would be High and a missing SPF record Medium. Re-test the TLS certificate and confirm `http://` redirects to `https://` with a 301/308 on the first hop.
5. **Confirm that the paths listed in robots.txt are protected by real access controls (Low, Security).** Verify that `/admin`, `/auth`, `/dashboard`, `/dev`, and `/api/` require authentication, and consider restricting `/dev` to internal networks. The other Low items (cookie and consent clarity, third-party embed disclosure, and the `X-Powered-By` header) are detailed in the sections above.