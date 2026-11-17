# Website Compliance & Security Audit Report

**Organization type:** Nonprofit
**Website:** owasp.org
**Scan date:** 2026-11-17
**Scan type:** Passive only. Publicly visible information was reviewed, with no penetration testing or attempts to break in.

---

## 1. Executive Summary

The passive scan indicates a **strong baseline of browser-level security protections**. All the major protective headers are present, including HTTPS enforcement (HSTS), clickjacking protection, and a detailed Content Security Policy.

The main gaps are:

- **Three checks could not be completed** (certificate/TLS, HTTP-to-HTTPS redirect, email spoofing protection). The scanner's DNS lookups failed for these, so they say nothing about the site itself. They should be re-run.
- **No privacy policy page was detected**, and there was no sign of a cookie notice even though the site mentions cookies.
- **3 of 8 images lack alternative text**, which is an accessibility issue.
- **The Content Security Policy allows inline scripts**, which weakens one of its main protections.

No Critical or High issues were identified from the available data.

**Note on scan reliability:** The scanner retrieved the homepage (HTTP 200) but failed on other lookups with "Name or service not known." This points to a scanner-side or network problem rather than a website fault. Items affected are marked **Not assessed** below, and no conclusions are drawn about them.

---

## 2. What Looks Good

| Area | Finding |
|---|---|
| HTTPS enforcement | HSTS is set for 1 year, covers subdomains, and is preload-enabled. |
| Clickjacking protection | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` are both set. |
| Content sniffing | `X-Content-Type-Options: nosniff` is present. |
| Privacy of referrals | Referrer-Policy is `strict-origin-when-cross-origin`. |
| Browser features | The Permissions-Policy disables camera, microphone, geolocation, and ad-tracking (FLoC) features. |
| CSP hardening | `object-src 'none'`, `base-uri 'self'`, `upgrade-insecure-requests`, and violation reporting are configured. |
| Tracking | No analytics or tracking tools were detected. |
| Accessibility basics | The page declares a language and has a title. |

---

## 3. Findings and Remediation

### Finding 1: TLS/certificate status could not be checked
- **Severity:** Not assessed (scanner error)
- **Explanation:** The certificate check failed with a DNS error. The HSTS header suggests HTTPS is in use, but certificate validity, expiry, and protocol versions were not verified.
- **Standards touched:** State breach-notification laws, GDPR/CCPA (security of personal data), and PCI-DSS if the organization accepts card payments.
- **Remediation:** Re-run the scan from a network with working DNS, or check the certificate manually with an SSL testing tool.

### Finding 2: HTTP-to-HTTPS redirect not verified
- **Severity:** Not assessed
- **Explanation:** The scanner could not fetch the plain `http://` version of the site. Visitors who type the address without "https" should be redirected automatically. HSTS helps with this, but only after a visitor's first secure visit.
- **Standards touched:** GDPR/CCPA (data-in-transit protection) and PCI-DSS (if payments are taken).
- **Remediation:** Confirm that `http://owasp.org` permanently (301) redirects to `https://owasp.org`.

### Finding 3: Email spoofing protections (SPF/DMARC) not verified
- **Severity:** Not assessed
- **Explanation:** The DNS lookup failed, so SPF, DKIM, and DMARC status are unknown. Missing or weak settings make it easier for scammers to send fake emails that appear to come from your domain, which is a common risk for nonprofits that email donors and members.
- **Standards touched:** State breach and fraud laws (phishing exposure) and general donor-trust obligations.
- **Remediation:** Check SPF, DKIM, and DMARC records with a DNS tool, and aim for a DMARC policy of `quarantine` or `reject`.

### Finding 4: No privacy policy detected; cookies mentioned without a visible consent notice
- **Severity:** Medium
- **Explanation:** The scan found no privacy or cookie policy pages, and no sign of a cookie banner, yet the page mentions cookies. Passive detection can miss links, so please verify manually. The scan found no analytics, which lowers the risk. However, the site's security policy permits connections to third-party services (Supabase for data, YouTube, Vimeo, Google Calendar), which suggests some visitor data may reach outside providers. A privacy policy should disclose this.
- **Standards touched:** GDPR (transparency and cookie consent for EU visitors), CCPA/CPRA (privacy notice for California residents), and COPPA if the site knowingly collects data from children under 13.
- **Remediation:**
  1. Publish a privacy policy and link it in the site footer.
  2. Disclose cookies and third-party services in it.
  3. Add a consent mechanism if any non-essential cookies are set.

### Finding 5: Images missing alternative text
- **Severity:** Medium
- **Explanation:** 3 of 8 images on the scanned page have no alt text. Screen-reader users get no description of these images. Purely decorative images should use an empty `alt=""`, but the scan cannot tell which case applies. This was a basic automated check, not a full accessibility audit.
- **Standards touched:** ADA and WCAG 2.1 AA (Success Criterion 1.1.1, Non-text Content).
- **Remediation:** Add meaningful alt text to informative images and `alt=""` to decorative ones. Then run a full audit with axe-core or Pa11y, as the scanner itself recommends.

### Finding 6: Content Security Policy allows inline scripts
- **Severity:** Medium
- **Explanation:** The policy includes `'unsafe-inline'` for scripts. This allows injected script code to run, which reduces the protection a CSP gives against cross-site scripting (XSS). This does not show that an XSS flaw exists, only that the safety net is weaker than it could be.
- **Standards touched:** State breach laws and GDPR/CCPA (protecting personal data). PCI-DSS requirement 6 would also apply if donation forms are on the site.
- **Remediation:** Move to nonce- or hash-based script allowances (supported by Next.js) and remove `'unsafe-inline'` from `script-src`.

### Finding 7: Broad wildcard sources in the CSP
- **Severity:** Low
- **Explanation:** Image sources include wildcards (`*.supabase.co`, `*.googleusercontent.com`). These are broader than necessary.
- **Standards touched:** General security hygiene.
- **Remediation:** Restrict these to the specific hostnames actually used.

### Finding 8: Technology disclosure in headers
- **Severity:** Low
- **Explanation:** The site reveals that it runs on Vercel and Next.js (`Server` and `X-Powered-By` headers). This is not a vulnerability by itself, but it tells attackers which known issues to look for.
- **Standards touched:** General security hygiene.
- **Remediation:** Disable the `X-Powered-By` header (`poweredByHeader: false` in Next.js config).

### Finding 9: robots.txt lists sensitive-sounding paths
- **Severity:** Low
- **Explanation:** The file lists `/admin`, `/api/`, `/auth`, `/dashboard`, `/dev`, and `/search`. This is a normal way to keep search engines out, but it also shows visitors where those areas are. There is no evidence these areas are unprotected.
- **Standards touched:** State breach laws and GDPR/CCPA (access control to personal data).
- **Remediation:** Confirm that these areas require authentication (ideally with multi-factor authentication for admin) and that `/dev` is not publicly reachable. Do not rely on robots.txt for protection.

---

## 4. Prioritized Action List

1. **Re-run the scan to complete the three unchecked items** (certificate/TLS, HTTP redirect, SPF/DKIM/DMARC). Right now these are unknowns, and email spoofing in particular is a common, high-impact risk for nonprofits.
2. **Publish or verify a privacy policy and cookie disclosure**, and add consent controls if non-essential cookies are used (GDPR/CCPA).
3. **Fix missing image alt text and run a full WCAG 2.1 AA audit** (ADA/WCAG).
4. **Tighten the Content Security Policy** by removing `'unsafe-inline'` from scripts and narrowing wildcard sources.
5. **Verify access controls on admin, dashboard, API, and dev areas** listed in robots.txt, including multi-factor authentication for administrators.

**Lower priority:** Remove the `X-Powered-By` header.

---

## 5. Limitations

This was a passive, non-intrusive review of publicly visible data from a single page load. It does not confirm the absence of vulnerabilities, cover back-end systems, or constitute a legal compliance determination. Items marked "Not assessed" were not checked. If the organization accepts card donations or collects data from minors, a targeted review against PCI-DSS or COPPA is recommended.