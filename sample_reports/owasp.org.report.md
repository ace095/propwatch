# Website Compliance & Security Audit Report

**Organization:** OWASP Foundation (nonprofit)
**Website:** owasp.org
**Scan type:** Passive, non-intrusive (no penetration testing)
**Scan date:** 17 Nov 2026
**Coverage:** 5 of 85 discovered pages were scanned in depth (home, contact, donate, about, mission, projects). The homepage got a full browser-based accessibility test. Robots.txt excluded 1 page.

---

## 1. Executive Summary

The passive scan indicates **strong technical security hygiene**. Encryption, browser-protection headers, and email anti-spoofing are all well configured. The main concerns are **accessibility on the donation page** and **no visible privacy policy**. Both matter for a nonprofit that collects donations and contact details.

| Area | Overall impression |
|---|---|
| Encryption (HTTPS/TLS) | Strong |
| Browser security headers | Strong, with one weakness (Medium) |
| Email spoofing protection | Good, with room to tighten |
| Privacy / cookie disclosure | Needs attention |
| Accessibility (ADA / WCAG 2.1 AA) | Needs attention, especially the donation form |

This is a passive review, so "no evidence of" a problem does not mean none exists. Applicable standards for a nonprofit are **ADA / WCAG 2.1 AA**, **CCPA/GDPR** (privacy and cookies), **state data-breach and privacy laws**, and **PCI-DSS** if card payments are handled. FERPA, COPPA, and HIPAA are not indicated for this sector, and the scan showed nothing that would trigger them.

---

## 2. Findings and Remediation

### Accessibility

#### 2.1 Donation form fields lack labels — **Critical**
- **What we found:** On `/donate`, the static check found 4 form fields without labels. The browser test (axe-core) confirmed 3 "critical" label violations, plus 1 "serious" issue where a hidden element can still be reached by keyboard (`aria-hidden-focus`).
- **Why it matters:** People using screen readers may not know what to enter in each field. This is the page where donations happen, so it creates both lost-donor risk and legal exposure.
- **Standards:** ADA / WCAG 2.1 AA, criteria 1.3.1 and 4.1.2.
- **Fix:** Give every field a visible, programmatically linked label (`<label for>` or `aria-label`). Remove focusable items from hidden regions, or stop hiding them. Retest with a screen reader.

#### 2.2 Insufficient text color contrast — **High**
- **What we found:** The browser test flagged color-contrast failures (rated "serious") on the homepage (1 element, a muted-gray intro paragraph) and the contact page (4 elements).
- **Why it matters:** Low-contrast text is hard to read for people with low vision or in bright light.
- **Standards:** ADA / WCAG 2.1 AA, criterion 1.4.3.
- **Fix:** Darken the "muted" text color in the design system to at least a 4.5:1 ratio against its background. Fixing the shared style should resolve every instance.

#### 2.3 No "skip to content" link on any scanned page — **Medium**
- **What we found:** None of the 5 scanned pages had a skip link.
- **Why it matters:** Keyboard and screen-reader users must tab through the entire navigation on every page.
- **Standards:** WCAG 2.1 A, criterion 2.4.1.
- **Fix:** Add a "Skip to main content" link as the first focusable element in the site-wide layout template.

#### 2.4 Heading structure — **Low**
- **What we found:** The homepage has 3 `h1` headings, and the projects page was also flagged.
- **Why it matters:** Inconsistent headings make navigation by screen reader harder.
- **Standards:** WCAG 1.3.1 / 2.4.6.
- **Fix:** Use one `h1` per page, with `h2`/`h3` below it.

**Positives:** All 8 homepage images have alt text. The page language and title are set. No keyboard traps or missing focus indicators were detected in the 60 tab stops tested. No mixed-content problems appeared on scanned pages.

**Limits:** The browser test covered only the homepage, with partial results for the contact and donate pages. One item needs manual review. The mission and projects pages were checked only by the static scan. Run a full audit of all key pages.

---

### Privacy

#### 2.5 No privacy policy found; no cookie notice detected — **High**
- **What we found:** No privacy policy pages or links were found on scanned pages. The site mentions cookies, but no cookie banner or consent mechanism was detected. No analytics were detected.
- **Why it matters:** The site has a donation form and a contact page, and its security policy references third-party services (see 2.8). Privacy laws such as CCPA/GDPR and state laws generally expect a clear policy explaining what data is collected and why.
- **Standards:** CCPA/GDPR, state privacy laws.
- **Fix:** Confirm whether a policy exists (it may live outside the scanned pages). If so, link it in the site-wide footer and on the donate and contact pages. If not, publish one covering donor data, cookies, and third-party processors. Add a consent tool if cookies beyond the strictly necessary are used. Cookie settings themselves were not checked.

---

### Payments

#### 2.6 Donation payment handling could not be determined — **Medium (verify)**
- **What we found:** `/donate` has one form and no password fields. The security policy lists no recognizable payment-processor domain. The scan cannot tell how card details are collected.
- **Why it matters:** If cards are handled on-site, PCI-DSS obligations are heavy. If they go to a hosted processor, the obligations are much lighter.
- **Standards:** PCI-DSS.
- **Fix:** Confirm that card entry happens on a PCI-compliant hosted page or embedded processor field, not on your own servers. Keep the matching self-assessment questionnaire on file. This is an item for verification, not an indication of a failure.

---

### Technical security

#### 2.7 Content Security Policy allows inline scripts — **Medium**
- **What we found:** The policy is otherwise thorough (framing blocked, objects blocked, reporting enabled), but `script-src` includes `'unsafe-inline'`.
- **Why it matters:** This weakens a key defense against cross-site scripting. If an attacker ever injected a script, the browser would be more likely to run it.
- **Standards:** Supports state breach-law "reasonable security" expectations and PCI-DSS (if applicable).
- **Fix:** Move to nonce- or hash-based script permissions (supported in Next.js) and remove `'unsafe-inline'` from `script-src`.

#### 2.8 Third-party services referenced in the policy — **Low (informational)**
- **What we found:** The policy permits connections to a Supabase backend (including live/websocket connections), Google (fonts, accounts, calendar, images), YouTube, and Vimeo.
- **Why it matters:** These parties may receive visitor data, so they should be described in your privacy policy, and you should have data-processing terms with them where required.
- **Standards:** CCPA/GDPR.
- **Fix:** Inventory these services and reflect them in your privacy disclosures.

#### 2.9 Technology disclosure and robots.txt path listing — **Low**
- **What we found:** The server announces "Vercel" and "Next.js". The robots.txt file lists `/admin`, `/api/`, `/auth`, `/dashboard`, `/dev`, and `/search`.
- **Why it matters:** This hands a curious attacker a map of sensitive areas. It is not a vulnerability by itself, since robots.txt is not an access control.
- **Fix:** Make sure those areas require authentication and are not publicly reachable. Where practical, remove the `X-Powered-By` header. Nothing was tested behind these paths.

#### 2.10 Email authentication — **Low**
- **What we found:** SPF is strict (`-all`). DMARC is set to `quarantine` with reporting enabled. DKIM could not be verified from the scan, since it uses org-specific selectors.
- **Why it matters:** This is good protection against spoofing of your domain, which matters for donor trust. Moving to `p=reject` gives the strongest protection.
- **Fix:** Confirm DKIM with your mail administrator. After reviewing DMARC reports for legitimate senders, move to `p=reject`.

#### 2.11 Certificate expiry — **Informational**
- **What we found:** The TLS certificate (Let's Encrypt, TLS 1.3) expires in 83 days (9 Feb 2027).
- **Fix:** Confirm that automatic renewal is in place and monitored.

**Positives:** The site uses TLS 1.3. HTTP redirects to HTTPS (308). HSTS is set with a one-year duration and preload. Clickjacking, content-type sniffing, referrer, and permissions headers are all configured, and no expected security headers were missing.

---

## 3. Prioritized Action List

1. **Label all donation-form fields and fix the hidden-but-focusable element** (2.1). This is the highest legal and mission impact.
2. **Publish or link a privacy policy and cookie disclosure** site-wide, and add consent controls if needed (2.5).
3. **Fix color contrast** in the shared design styles (2.2).
4. **Add a skip-to-content link** and fix heading structure in the global layout (2.3, 2.4).
5. **Remove `'unsafe-inline'` from the script policy** using nonces/hashes (2.7).

**Next in line:**
- Verify the payment flow for PCI-DSS scope (2.6).
- Review the public path list and make sure sensitive areas require authentication (2.9).
- Confirm DKIM and tighten DMARC (2.10).
- Confirm certificate auto-renewal (2.11).
- Document third-party data processors (2.8).
- Commission a full accessibility audit and an authorized security assessment to go beyond passive findings.

---

*This report reflects passive, point-in-time observations of publicly available information. It is not a penetration test or a legal opinion, and it does not certify compliance with any standard.*