# Website Compliance & Security Audit Report

**Organization:** owasp.org (Nonprofit)
**Scan date:** 2026-11-17
**Scan type:** Passive (publicly visible information only)

> **Scope note:** This audit used only publicly observable information. The site was not penetration-tested, and nothing here proves it is secure or vulnerable. Findings describe what the scan *indicates*. Items the scan did not check are listed at the end.

---

## 1. Executive Summary

The site's technical foundation is strong. It uses modern encryption (TLS 1.3), forces HTTPS, and sets a full set of browser security protections. Its email anti-spoofing setup is also well above average.

The scan found no Critical issues. The main gaps are in **privacy compliance** and **accessibility**, plus a few hardening opportunities:

| # | Finding | Severity | Main standard |
|---|---------|----------|---------------|
| 1 | No privacy policy page located; no cookie consent indicator | **High** | CCPA / GDPR, state privacy laws |
| 2 | 3 of 8 images lack alternative text | **Medium** | ADA / WCAG 2.1 AA |
| 3 | Content Security Policy allows `'unsafe-inline'` scripts | **Medium** | State breach laws, GDPR (data protection) |
| 4 | DMARC set to "quarantine," not "reject"; DKIM not verified | **Low–Medium** | State breach laws (phishing risk) |
| 5 | Third-party embeds and services may share visitor data | **Low–Medium** | CCPA / GDPR |
| 6 | `robots.txt` lists sensitive-sounding paths | **Low** | General security hygiene |
| 7 | Technology stack disclosed (Next.js, Vercel) | **Low** | General security hygiene |
| 8 | Certificate expires in 83 days | **Low (informational)** | General availability / trust |

---

## 2. Detailed Findings

### 1. No privacy policy located; no cookie banner indicator: **High**
**What we saw:** The scan found no privacy-policy pages and no sign of a cookie consent banner. The site does mention cookies, and no analytics tools were detected.

**Why it matters:** The site appears to support sign-in (the content policy permits Google account forms, and `/auth` and `/dashboard` paths exist), which suggests it collects personal information. Privacy laws generally expect a clear, findable privacy notice. Where the law applies, they also expect disclosure of cookies and third-party data sharing, and sometimes consent. The scan may simply have missed a policy hosted at an unusual address, so confirm this manually.

**Standards:** CCPA/CPRA (California visitors), GDPR/ePrivacy (EU/UK visitors), other state privacy laws.

**Remediation:** Confirm a privacy policy exists and is linked from every page footer. If not, publish one covering what data is collected, why, who receives it (e.g., Supabase, Google, video providers), and how users can request access or deletion. Add a cookie notice or consent tool if non-essential cookies or third-party embeds are used.

### 2. Images missing alternative text: **Medium**
**What we saw:** On the page scanned, 3 of 8 images (about 38%) had no `alt` text. The page language and title are correctly set, which is good.

**Why it matters:** Screen-reader users cannot understand images without descriptions. This is one of the most common triggers for web accessibility complaints.

**Standards:** WCAG 2.1 AA (Success Criterion 1.1.1), ADA. Nonprofits that serve the public are not exempt from accessibility expectations.

**Remediation:** Add meaningful `alt` text to informative images and empty `alt=""` to purely decorative ones. Because this check was a basic HTML scan of one page, run a full automated and manual audit (axe-core, Pa11y, keyboard and screen-reader testing) across key pages.

### 3. Content Security Policy allows inline scripts: **Medium**
**What we saw:** The site has a detailed CSP, which is a strength. However, `script-src` includes `'unsafe-inline'`, which weakens one of the CSP's main purposes: blocking injected malicious scripts (cross-site scripting). `style-src` also allows inline styles, which is a lower risk.

**Why it matters:** If an attacker ever found a way to inject content into a page, this setting would make it easier for that script to run. That could expose user sessions or personal data.

**Standards:** State data-breach laws and GDPR security obligations (reasonable safeguards for personal data).

**Remediation:** Move to nonce-based or hash-based script allowances, which Next.js supports, and remove `'unsafe-inline'` from `script-src`. Test in report-only mode first. The site already has a CSP report endpoint (`/api/csp-report`), which will help.

### 4. DMARC "quarantine" policy; DKIM not verified: **Low–Medium**
**What we saw:**
- SPF is present and strict (`-all`), authorizing Google, Mailchimp, and Amazon SES.
- DMARC is present with reporting enabled, but its policy is `quarantine`, not the strongest setting, `reject`.
- DKIM could not be confirmed, because it uses organization-specific selectors.

**Why it matters:** Strong email authentication makes it harder for criminals to send fake emails (e.g., fake donation or membership requests) that appear to come from your domain.

**Standards:** State breach and fraud-prevention expectations; general phishing defense.

**Remediation:** Have your mail administrator verify DKIM for every sending service. After reviewing the DMARC reports for legitimate mail being flagged, move the policy to `p=reject`.

### 5. Third-party services and embeds: **Low–Medium**
**What we saw:** The site's policy allows connections to Supabase (data and real-time connections), YouTube (including the privacy-enhanced `youtube-nocookie` domain), Vimeo, Google Calendar, Google accounts, Unsplash, and others.

**Why it matters:** Embedded third-party content can transmit visitor IP addresses and set cookies. The scan did not examine what is actually loaded or which cookies are set.

**Standards:** CCPA/GDPR (disclosure and consent).

**Remediation:** Inventory third-party services, list them in the privacy policy, prefer privacy-enhanced embed modes (e.g., `youtube-nocookie.com` only), and remove the allowances for any unused services (e.g., plain `youtube.com`, Vimeo).

### 6. `robots.txt` reveals sensitive paths: **Low**
**What we saw:** `robots.txt` lists `/admin`, `/api/`, `/auth`, `/dashboard`, `/dev`, and `/search`.

**Why it matters:** This file is public and can point attackers to areas of interest. It is not a vulnerability by itself, but those areas must be protected on their own merits. The `/dev` path in particular suggests development content, which should not be publicly reachable.

**Standards:** General security hygiene.

**Remediation:** Confirm these paths require authentication and are not exposed. Rely on access controls, not `robots.txt`, for protection. Remove or restrict `/dev` on the production site if it is not needed.

### 7. Technology disclosure: **Low**
**What we saw:** Response headers reveal `Server: Vercel` and `X-Powered-By: Next.js`.

**Why it matters:** This helps attackers target known weaknesses in specific software. The risk is minor.

**Remediation:** Disable the `X-Powered-By` header (in Next.js, set `poweredByHeader: false`). Keep the framework up to date.

### 8. Certificate expiry in 83 days: **Low (informational)**
**What we saw:** The TLS certificate (Let's Encrypt) expires on Feb 9, 2027.

**Why it matters:** Let's Encrypt certificates are short-lived by design and normally renew automatically. An expired certificate would trigger browser warnings and erode donor and member trust.

**Remediation:** Confirm automatic renewal works and set up expiry monitoring and alerts.

---

## 3. What's Working Well
- **Encryption:** TLS 1.3, and HTTP traffic is redirected to HTTPS (308 redirect).
- **HSTS:** One-year duration, includes subdomains, preload enabled.
- **Browser protections:** X-Frame-Options (DENY), X-Content-Type-Options, Referrer-Policy, and Permissions-Policy are all present. Camera, microphone, and geolocation are disabled. No expected security headers were missing.
- **Clickjacking and plugin protection:** `frame-ancestors 'none'` and `object-src 'none'`.
- **Email security:** Strict SPF and a DMARC policy with reporting.
- **Accessibility basics:** Page language and title are set.

---

## 4. Not Checked / Limitations
- **PCI-DSS:** The scan did not determine whether the site processes donations or card data. If it does, confirm payments go through a PCI-compliant provider (e.g., a hosted checkout).
- DKIM configuration (needs mail admin verification).
- Actual cookies set, consent behavior, and the contents of third-party embeds.
- Full WCAG 2.1 AA compliance (only a basic check of one page was done).
- Application-level security, authentication, subdomains, and server configuration beyond public headers.

---

## 5. Prioritized Action List

1. **Publish or verify a privacy policy and cookie/consent notice** linked sitewide, and disclose third-party data recipients. (Finding 1)
2. **Fix missing image alt text and commission a full WCAG 2.1 AA audit.** (Finding 2)
3. **Tighten the Content Security Policy** by removing `'unsafe-inline'` from `script-src` using nonces or hashes. (Finding 3)
4. **Verify DKIM and move DMARC to `p=reject`** after reviewing reports. (Finding 4)
5. **Review third-party embeds and trim unused allowances**, then confirm that admin, dev, and API paths are properly access-controlled. (Findings 5 and 6)

*Also:* hide the `X-Powered-By` header, and monitor certificate auto-renewal. If the organization accepts donations, verify PCI-DSS responsibilities with the payment provider.