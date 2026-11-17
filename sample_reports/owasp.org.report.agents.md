# Website Audit: owasp.org (Nonprofit)

## Executive Summary

This passive audit covers security, privacy, and accessibility for owasp.org. The site's technical foundation is strong: TLS 1.3, HSTS with preload, a full set of security headers, and strict email authentication (SPF `-all`, DMARC enforced). There are no Critical issues. The most severe finding is a **High** accessibility issue, insufficient colour contrast on body text. Three **Medium** items follow: a CSP that allows `'unsafe-inline'` scripts, no discoverable privacy policy, and no skip-to-content link. The remaining findings are Low or informational hardening and best-practice items. These results come from passive and automated checks only. They are not a penetration test or legal review, and manual accessibility testing and confirmation of DKIM signing are still recommended.

---

## Security
**Transport & Infrastructure Security: owasp.org (Nonprofit)**

Overall, the passive findings indicate a strong transport and email-authentication posture. There are no Critical or High issues. A few low-to-medium hardening items remain.

**What looks good**
- **TLS:** TLS 1.3, with a Let's Encrypt certificate valid for 83 more days (expires Feb 9, 2027). This is normal for a short-lived, auto-renewed certificate.
- **HTTP to HTTPS:** Plain HTTP returns a 308 redirect to `https://owasp.org/`. The `redirects_to_https: null` value in the header check is just the HTTPS response itself, not a gap.
- **HSTS:** `max-age=31536000; includeSubDomains; preload`.
- **Other headers:** X-Frame-Options (DENY), X-Content-Type-Options (nosniff), Referrer-Policy, Permissions-Policy and a CSP are all present. No headers are reported missing.
- **Email authentication:** SPF ends in `-all` (hard fail) and DMARC is enforced at `p=quarantine` with reporting enabled.

**Issues**

1. **CSP allows `'unsafe-inline'` for scripts: Medium**
   - **Explanation:** `script-src 'self' 'unsafe-inline'` indicates the policy would not block injected inline scripts. That weakens the main protection a CSP gives against cross-site scripting (XSS). The rest of the policy is tight (`object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`).
   - **Standard:** PCI-DSS Req. 6.4 and 11.6.1 (script control on payment pages, if donations are taken on-site), and general data-in-transit and web-app hardening expectations.
   - **Fix:** Replace `'unsafe-inline'` with per-request nonces or hashes. Next.js supports nonce-based CSP through middleware. Consider `'strict-dynamic'` as well. Test in Report-Only mode first, using the existing `/api/csp-report` endpoint.

2. **DMARC is `quarantine`, not `reject`: Low**
   - **Explanation:** Spoofed mail claiming to be from owasp.org would likely land in spam but is not rejected outright. For a well-known brand, that leaves a small phishing window.
   - **Standard:** Anti-phishing best practice. State breach laws and PCI-DSS 12.6 are indirectly relevant, since phishing is a common breach entry point.
   - **Fix:** Review the aggregate (`rua`) reports. Once all legitimate senders (Google, Mailchimp, Amazon SES) pass SPF or DKIM alignment, move to `p=reject`. Optionally step up gradually with `pct=`.

3. **Technology disclosure in headers: Low (informational)**
   - **Explanation:** `Server: Vercel` and `X-Powered-By: Next.js` reveal the platform and framework. This is not a vulnerability in itself, but it helps attackers target known issues.
   - **Standard:** General hardening guidance (e.g., OWASP Secure Headers).
   - **Fix:** Set `poweredByHeader: false` in `next.config.js`. The `Server` header on Vercel is generally not configurable, so treat that part as accepted.

4. **robots.txt lists sensitive-sounding paths: Low (informational)**
   - **Explanation:** The disallow rules (`/admin`, `/dev`, `/auth`, `/dashboard`) suggest that these paths exist. This was not tested, and there is no evidence they are exposed.
   - **Standard:** General information-disclosure hygiene.
   - **Fix:** Don't rely on robots.txt for protection. Make sure these paths enforce authentication, and consider restricting `/dev` and `/admin` by network or SSO. Remove entries that don't need to be advertised.

**Not verified**
- DKIM was not checked, because it uses org-specific selectors. The mail admin should confirm that signing is active for all senders.
- Certificate auto-renewal can't be confirmed passively. Keep expiry monitoring in place.

---

## Privacy
## Privacy & Data-Handling Assessment: owasp.org

These are passive findings only. They indicate how the site is configured but are not a penetration test or a legal review.

### Issue 1: No privacy policy page or links detected
- **Severity:** Medium
- **What we found:** The passive scan found no privacy or policy pages and no policy links (`policy_pages_found` and `policy_links_found` are both empty). The site does mention cookies (`mentions_cookies: true`), which suggests some cookie or tracking disclosure exists somewhere, but we found no linked policy.
- **Why it matters:** Visitors may not be able to learn what data is collected, why, or how to exercise their rights. The site also connects to a Supabase backend and embeds YouTube, Vimeo, and Google Calendar content. Those services can receive visitor data such as IP addresses.
- **Standard:** CCPA/GDPR (transparency and notice requirements). COPPA and FERPA are probably not directly relevant for this nonprofit, unless the site knowingly serves children under 13.
- **Fix:** Publish a clear privacy policy and link it from the site-wide footer. It should cover:
  - what is collected (accounts, forms, logs);
  - the third parties involved (Supabase, YouTube, Vimeo, Google);
  - cookie use;
  - retention periods;
  - how to contact the organization about data requests.

  If a policy already exists but wasn't detected (for example, it's rendered by JavaScript), make sure it is reachable through a standard footer link.

### Issue 2: Cookies mentioned, but no consent mechanism detected
- **Severity:** Low
- **What we found:** The site mentions cookies, but no cookie banner was detected (`cookie_banner_hint: false`). **No analytics was detected** (`has_analytics: false`), so there is no evidence of tracking that would require prior consent.
- **Why it matters:** If only strictly necessary cookies are used, a consent banner may not be required. However, the cookie mention and the third-party embeds (YouTube, Vimeo) could set cookies or transmit data once loaded. This is a possible gap, not a confirmed violation.
- **Standard:** GDPR/ePrivacy and CCPA (consent and disclosure for non-essential cookies).
- **Fix:** Audit which cookies are actually set. If any are non-essential, add a consent mechanism. Document the cookies in the privacy policy. Using `youtube-nocookie.com` (already allowed in the CSP) for all YouTube embeds reduces tracking exposure.

### Positive findings
- **Referrer policy:** `strict-origin-when-cross-origin` is a sound setting. It limits URL leakage to other sites, so there is no concern here.
- **Permissions-Policy:** Camera, microphone, and geolocation are disabled, and `interest-cohort=()` opts out of FLoC-style ad profiling. This is privacy-protective.
- **Transport and framing protections:** HSTS (with preload), a restrictive CSP (`frame-ancestors 'none'`, `object-src 'none'`), `X-Frame-Options: DENY`, and `nosniff` are all present. No security headers were reported missing.
- **Email authentication:** SPF uses a strict `-all`, and DMARC is set to `p=quarantine` with reporting enabled. This reduces the risk of spoofed email that could be used to phish constituents. DKIM was not verified and needs confirmation by the mail administrator.

### Minor note
- The CSP allows `'unsafe-inline'` for scripts. This is primarily a security hardening matter, not a privacy one, and is outside this section's scope. It is noted only for the security review.
- `redirects_to_https` was not determined (null), so it was not checked here. HSTS being present suggests HTTPS is enforced.

### Summary
The main gap is the apparent absence of a discoverable privacy policy (Medium). Headers and email authentication are well configured, and no analytics or tracking was detected.

---

## Accessibility
## Accessibility Assessment: owasp.org (Nonprofit)

These are passive findings from static HTML checks and an axe-core 4.12.1 browser run, which included a keyboard Tab test. Overall, the results suggest a fairly solid baseline: 23 axe rules passed, with one serious violation and two lower-severity structural issues. Automated tools catch only part of the possible issues, so manual review is still advised (axe flagged 1 item as `needs_manual_review`).

### Issues

**1. Insufficient colour contrast on body text: High**
- **What it is:** One paragraph ("Stay connected with the global AppSec community through O…") uses the `text-ink-muted` colour class. axe reports that its text/background contrast falls below the minimum threshold. This indicates some users with low vision or colour-vision deficiencies, or anyone reading in bright light, may struggle to read it.
- **Standard:** WCAG 2.1 AA, 1.4.3 Contrast (Minimum): 4.5:1 for normal text.
- **Fix:** Darken the `text-ink-muted` colour (or lighten the background) until the ratio is at least 4.5:1. Check the same token anywhere else it's used, since only one element was flagged here but the muted colour may be reused elsewhere on other pages or states.

**2. No skip-to-content link: Medium**
- **What it is:** The static check found no skip link near the top of the page. Keyboard and screen-reader users may have to tab through the whole navigation on every page before reaching the main content. This matters here because the keyboard test found 100 focusable elements on the page.
- **Standard:** WCAG 2.1 A, 2.4.1 Bypass Blocks.
- **Fix:** Add a "Skip to main content" link as the first focusable element, pointing to the `<main>` landmark (e.g. `<a href="#main">`). It can be visually hidden until focused.

**3. Multiple h1 elements (3 found): Low**
- **What it is:** The page has three `<h1>` elements rather than one. This can blur the page's heading hierarchy for screen-reader users who navigate by headings. Note that HTML5 doesn't strictly forbid multiple h1s, so this is a best-practice concern more than a hard failure.
- **Standard:** WCAG 2.1 A, 1.3.1 Info and Relationships; AA, 2.4.6 Headings and Labels.
- **Fix:** Use a single `<h1>` for the main page topic and demote the others to `<h2>`/`<h3>` to reflect the actual structure.

### Keyboard and Other Checks (No Issues Found)
- **Visible focus:** No elements without a visible focus style were found (`no_visible_focus_style` is empty), which suggests focus indication is handled well (WCAG 2.4.7).
- **Keyboard traps:** No evidence of a keyboard trap (WCAG 2.1.2).
- **Coverage note:** The Tab test reached 60 of 100 focusable elements within the 60 presses checked. This is a test limit, not a finding, but the remaining 40 were not verified by this test.
- **Basics:** The page has a `lang` attribute and a title, and all 8 images have alt text (WCAG 3.1.1, 2.4.2, 1.1.1). Alt text presence doesn't confirm that the text is meaningful.

### Recommended Next Step
Fix the contrast issue first, then add the skip link. Follow up with manual testing (screen reader, keyboard-only navigation across the full page, and the 1 axe item flagged for review) to cover what automation can't.

---

## Top 5 Fixes (Ordered by Severity)

| # | Fix | Area | Severity |
|---|-----|------|----------|
| 1 | **Raise colour contrast** on the `text-ink-muted` token to at least 4.5:1, and check other places the token is used. | Accessibility | High |
| 2 | **Remove `'unsafe-inline'` from the CSP `script-src`**, using nonces or hashes (and optionally `'strict-dynamic'`). Test in Report-Only mode via `/api/csp-report` first. | Security | Medium |
| 3 | **Publish a privacy policy** and link it from the site-wide footer. It should name third parties (Supabase, YouTube, Vimeo, Google), cookie use, retention, and a contact for data requests. If one already exists, make it reachable by a standard footer link. | Privacy | Medium |
| 4 | **Add a skip-to-content link** as the first focusable element, pointing to the `<main>` landmark. | Accessibility | Medium |
| 5 | **Audit the cookies actually set**, add consent if any are non-essential, document them in the privacy policy, and use `youtube-nocookie.com` for all YouTube embeds. | Privacy | Low |

**Next in line (all Low):** move DMARC to `p=reject` after reviewing `rua` reports, consolidate to a single `<h1>`, set `poweredByHeader: false`, and review the paths listed in robots.txt. Also confirm DKIM signing with the mail administrator, and complete manual accessibility testing.