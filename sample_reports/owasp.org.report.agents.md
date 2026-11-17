# Website Audit: owasp.org (Nonprofit)

## Executive Summary

This audit combines passive security, privacy, and accessibility reviews of owasp.org. Transport security is strong: TLS 1.3, HSTS with preload, a full set of security headers, and strict email authentication. No Critical or High issues were found. Three Medium-severity items need attention: a Content Security Policy that allows inline scripts, no detected privacy policy page, and images missing alt text. Several Low-severity hardening items concern email spoofing protection, technology disclosure, and cookie notice. All findings come from passive observation, so they indicate posture rather than prove the absence of vulnerabilities. The accessibility check in particular covers only basic HTML signals on one page, and a full WCAG audit is still needed.

*Note on a difference between sections: the Security section reports that the HTTP-to-HTTPS redirect was confirmed by a dedicated check (308 to `https://owasp.org/`). The Privacy section notes that the header-based redirect check returned no result. The Security section explains this: the header check reported null, but the dedicated check confirmed the redirect.*

---

## Security

# Transport & Infrastructure Security: owasp.org

**Summary:** The passive findings indicate a strong transport security posture. There are no Critical or High issues. A few lower-severity hardening items are listed below.

## What looks good
- **TLS:** TLSv1.3, with a Let's Encrypt certificate valid for 83 more days (expires Feb 9, 2027).
- **HTTP to HTTPS:** Plain HTTP returns a 308 redirect to `https://owasp.org/`. The header check reported `redirects_to_https: null`, but the dedicated redirect check confirms the redirect works.
- **HSTS:** `max-age=31536000; includeSubDomains; preload`, which is a strong setting.
- **Other headers:** X-Frame-Options (DENY), X-Content-Type-Options (nosniff), Referrer-Policy, and Permissions-Policy are all present. The CSP also sets `frame-ancestors 'none'`, `object-src 'none'`, and `upgrade-insecure-requests`.
- **Email authentication:** SPF ends in `-all` (strict). DMARC is enforcing (`p=quarantine`) with reporting configured.

## Issues

### 1. CSP allows `'unsafe-inline'` for scripts (Medium)
- **Explanation:** `script-src 'self' 'unsafe-inline'` lets inline scripts run. This weakens the CSP's main purpose, which is limiting the damage of a cross-site scripting (XSS) flaw. An injected inline script would not be blocked by the policy. This is a common trade-off with Next.js, but it is still a gap.
- **Standard:** PCI-DSS Req. 6 (secure development) and 6.4 / 11.6 script controls if payment pages are in scope. It also bears on general data-in-transit and web-app protection expectations.
- **Fix:** Move to nonce-based or hash-based CSP (Next.js supports nonces via middleware) and remove `'unsafe-inline'` from `script-src`. Use the existing `report-uri` to find breakage before enforcing.

### 2. DMARC policy is `quarantine`, not `reject` (Low)
- **Explanation:** Spoofed mail that fails authentication is sent to spam rather than rejected outright. For a well-known organization, impersonation and phishing remain an attractive target.
- **Standard:** Not a mandated requirement. It is a best practice for anti-phishing and donor/member trust.
- **Fix:** Review the aggregate reports (`rua`) to confirm all legitimate senders (Google, Mailchimp, Amazon SES) pass. Then move to `p=reject`, optionally stepping up with `pct=`.

### 3. DKIM not verified (Low / informational)
- **Explanation:** DKIM uses org-specific selectors, so this passive scan could not confirm it. This is a gap in the check, not evidence of a problem.
- **Standard:** Supports DMARC alignment.
- **Fix:** Have the mail administrator confirm DKIM signing is enabled for every sending service listed in SPF.

### 4. Technology disclosure in headers and robots.txt (Low)
- **Explanation:** The response headers reveal `Server: Vercel` and `X-Powered-By: Next.js`. `robots.txt` also lists `/admin`, `/dashboard`, `/dev`, and `/auth`. This is not a vulnerability by itself, but it gives attackers a roadmap of the platform and likely sensitive paths.
- **Standard:** General hardening (OWASP ASVS information-leakage guidance).
- **Fix:** Disable the header with `poweredByHeader: false` in `next.config.js`. Make sure the listed paths require authentication and are not reachable in production (especially `/dev`). Don't rely on robots.txt for protection.

### 5. Certificate renewal window (Informational)
- **Explanation:** 83 days remaining is normal for Let's Encrypt's short-lived certificates. There is no sign of a problem, but a failed auto-renewal would eventually become a Critical outage.
- **Standard:** PCI-DSS Req. 4 (strong cryptography in transit).
- **Fix:** Confirm automated renewal is working and set up expiry monitoring or alerts, for example at 30 and 14 days.

**Scope note:** These conclusions come only from passive observation. They suggest the configuration is sound but do not prove the absence of vulnerabilities.

---

## Privacy

## Privacy & Data-Handling Assessment: owasp.org (Nonprofit)

These are passive observations only. They indicate posture but do not show how data is handled behind the scenes.

**Overall:** The privacy posture looks reasonably strong in the technical controls. The main gap is that no privacy policy page was detected.

### Issue 1: No privacy policy page detected
- **Severity:** Medium
- **Explanation:** The passive scan found no privacy policy page (`policy_pages_found` is empty). The site does mention cookies, which suggests some cookie or storage use that visitors should be told about. The site also connects to Supabase, which suggests user or account data may be handled. A policy may exist at a path the scan did not check, so this indicates a possible gap rather than confirming one.
- **Standard:** CCPA/GDPR (transparency and notice requirements). FERPA and COPPA are not clearly relevant to a general nonprofit site, but would apply if the site knowingly collects data from children under 13.
- **Fix:** Publish a clear privacy policy and link it from the site footer on every page. It should cover what data is collected, why, who receives it (e.g., Supabase, YouTube, Vimeo, Google), retention, and how visitors can exercise their rights. Also confirm whether a policy already exists at a non-standard URL and make it easy to find.

### Issue 2: Cookies mentioned, but no cookie banner/consent mechanism detected
- **Severity:** Low
- **Explanation:** The site mentions cookies, but no cookie banner hint was detected. No analytics were detected (`has_analytics: false`), so the consent risk is lower than for a site loading trackers with no notice. Embedded third-party content (YouTube, Vimeo, Google Calendar) can still set cookies or share visitor data, and the site's CSP permits these. The CSP does list `youtube-nocookie.com`, which is a privacy-friendly choice, if that domain is actually used for embeds.
- **Standard:** GDPR/ePrivacy and CCPA (consent and notice for non-essential cookies).
- **Fix:** Confirm which cookies are set. If only strictly necessary ones are used, document that in the privacy policy. If embeds set non-essential cookies, load them only after consent (click-to-load) or use the `youtube-nocookie.com` domain consistently.

### Positive findings (no action needed)
- **Referrer policy:** `strict-origin-when-cross-origin` limits URL leakage to other sites. No evidence of a permissive setting.
- **Permissions-Policy:** Camera, microphone, and geolocation are disabled, and `interest-cohort=()` opts out of FLoC-style tracking. This supports visitor privacy.
- **No analytics detected:** No evidence of third-party analytics tracking visitors.
- **Transport security:** HSTS with preload and `upgrade-insecure-requests` protect data in transit. (The HTTPS redirect check returned no result, so it was not confirmed.)
- **Email authentication:** SPF uses a strict `-all`, and DMARC is set to `quarantine` with reporting. This helps protect supporters from spoofed emails. DKIM was not verified by this scan.

### Notes
- The CSP allows `'unsafe-inline'` for scripts. This is primarily a security matter rather than a privacy one, but it weakens protection against script injection that could expose visitor data.
- The CSP `report-uri` collects violation reports. If those reports contain visitor details such as URLs or IPs, mention it in the privacy policy.

---

## Accessibility

## Accessibility Assessment: owasp.org (Passive Signals Only)

This is a limited, passive check of the page's HTML (parsed with BeautifulSoup). It indicates some basic accessibility hygiene but is not a substitute for a full WCAG 2.1 AA audit.

### Issue 1: Images missing alt text
- **Severity:** Medium
- **What we found:** 3 of the 8 images (about 38%) have no alt attribute.
- **Why it matters:** Screen reader users get no description of these images, or hear the file name instead. If the images carry meaning (charts, logos, calls to action, linked images), that information is lost to blind and low-vision visitors. For a nonprofit with a public education mission, this directly affects who can use its content.
- **Standard:** WCAG 2.1 SC 1.1.1 Non-text Content (Level A), relevant to ADA compliance.
- **Fix:**
  - Add concise, meaningful alt text to informative images (e.g., `alt="OWASP Top 10 project logo"`).
  - For purely decorative images, use an empty `alt=""` so assistive technology skips them.
  - For images inside links or buttons, make the alt text describe the destination or action.
  - Add a template or CI check so new content cannot be published without alt attributes.
  - Note: this check cannot tell whether the 3 images are decorative, so some may only need `alt=""`.

### Items that passed
- **Language attribute:** The `lang` attribute is present on the page. This supports correct screen reader pronunciation (WCAG 3.1.1). This check did not verify that the value is correct.
- **Page title:** A page title is present (WCAG 2.4.2). This check did not assess whether it is descriptive or unique.

### Important limitation
These results come only from passive HTML signals on the page tested. They say nothing about color contrast, keyboard navigation, focus order, form labels, ARIA usage, heading structure, link text quality, or dynamic content. **A full audit with axe-core or Pa11y, plus manual testing with a screen reader and keyboard-only navigation, is still needed** to assess WCAG 2.1 AA conformance. A single page's results also may not represent the rest of the site.

---

## Top 5 Fixes (Ordered by Severity)

The first three items are all Medium severity and are listed in no strict order of priority among themselves. Items 4 and 5 are Low severity.

1. **Remove `'unsafe-inline'` from the CSP `script-src` (Medium, Security).** Move to a nonce- or hash-based policy, using the existing `report-uri` to catch breakage before enforcing.
2. **Publish and link a privacy policy (Medium, Privacy).** First confirm whether one already exists at a non-standard URL. It should cover data collected, recipients (e.g., Supabase, YouTube, Vimeo, Google), retention, visitor rights, and cookie use.
3. **Add alt text to the 3 images missing it (Medium, Accessibility).** Use descriptive text for informative images and `alt=""` for decorative ones. Add a template or CI check to prevent regressions.
4. **Reduce technology disclosure and verify the paths listed in robots.txt (Low, Security).** Set `poweredByHeader: false`, and confirm that `/admin`, `/dashboard`, `/dev`, and `/auth` require authentication and that `/dev` is not reachable in production.
5. **Move DMARC from `quarantine` to `reject` (Low, Security).** Review aggregate reports first to confirm that all legitimate senders (Google, Mailchimp, Amazon SES) pass, and have the mail administrator confirm DKIM signing for each sender.

*Also worth tracking, though lower priority: confirm which cookies are set and how embeds are loaded (Privacy, Low), and set up certificate expiry monitoring (Security, Informational).*