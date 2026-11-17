# Website Compliance & Security Audit Report

**Target:** example.com
**Sector:** Small business
**Scan date:** 17 November 2026
**Scan type:** Passive (publicly visible information only)

---

## 1. Executive Summary

This was a passive, outside-in review. It was not a penetration test, so it cannot confirm that the site is secure or vulnerable.

**Overall picture:** The site has a modern encryption foundation and unusually strong email anti-spoofing settings. However, the **unencrypted (HTTP) version of the site is not redirected to HTTPS**, and **none of the six standard browser security headers are set**. There is also **no privacy policy**, and **two minor accessibility gaps**.

The scan found only a very small site: one focusable element, no images, and no additional pages discovered. This may be a landing page or placeholder. Findings about forms, payments, and customer data could not be assessed from this scan.

| Area | Result |
|---|---|
| Encryption (TLS) | Good (TLS 1.3), certificate renewal due in 38 days |
| HTTP to HTTPS redirect | Not in place |
| Browser security headers | 0 of 6 present |
| Email spoofing protection | Strong |
| Privacy documentation | None found |
| Accessibility (automated) | No violations in browser test, 2 minor static-HTML gaps |

---

## 2. Findings

### 2.1 HTTP version does not redirect to HTTPS: **Medium**
**What we saw:** Requesting the plain `http://` address returned a normal page (status 200) instead of sending visitors to the secure `https://` version.

**What it means:** Anyone who types the address without "https" or follows an old link may load the site over an unencrypted connection. On public Wi-Fi, that traffic could be read or altered.

**Standards touched:**
- PCI-DSS (Req. 4): applies if you ever take or transmit card data.
- CCPA/GDPR and state data-breach laws: these expect "reasonable security" for personal data.

**Fix:** In Cloudflare, enable **"Always Use HTTPS"** (SSL/TLS, then Edge Certificates). This takes about a minute.

### 2.2 HSTS header missing: **Medium**
**What we saw:** The `Strict-Transport-Security` header is absent.

**What it means:** HSTS tells browsers to always use the secure version of your site. Without it, the redirect gap above is easier to exploit.

**Standards touched:** PCI-DSS (if cards are handled), CCPA/GDPR "reasonable security."

**Fix:** Enable HSTS in Cloudflare (Edge Certificates, then HSTS). Start with a short duration and increase it once you confirm everything works over HTTPS. Fix 2.1 first.

### 2.3 Content-Security-Policy (CSP) missing: **Medium**
**What it means:** CSP limits which scripts and resources can run on your pages. It is a main defense against malicious code injection (cross-site scripting). Because this site appears very simple, the current exposure likely depends on what you add later.

**Standards touched:** PCI-DSS (Req. 6.4 / 11.6 on payment-page scripts, if applicable), CCPA/GDPR/breach laws.

**Fix:** Have your web developer add a CSP, ideally starting in "report-only" mode so nothing breaks.

### 2.4 Other missing security headers: **Low**
| Header | Purpose |
|---|---|
| X-Frame-Options | Prevents your site being embedded in a hidden frame (clickjacking) |
| X-Content-Type-Options | Stops browsers guessing file types |
| Referrer-Policy | Limits what visitor info is passed to other sites |
| Permissions-Policy | Restricts camera, microphone, and location features |

**Standards touched:** General security best practice. Referrer-Policy has a mild privacy link (CCPA/GDPR).

**Fix:** Add all four at once using Cloudflare Transform Rules (response header modification) or your hosting configuration.

### 2.5 No privacy policy found: **Medium**
**What we saw:** No privacy policy page or links were detected, and the site has no cookie notice. The scan found no analytics or tracking tools and no evidence of a cookie banner.

**What it means:** With no analytics detected, a cookie banner may not be needed today. But if you collect any personal information (contact forms, email sign-ups, orders) or add analytics or advertising tools, a privacy policy is generally required.

**Standards touched:** CCPA/CPRA (California), GDPR (if you serve EU visitors), and state privacy laws. California's online privacy law (CalOPPA) requires a posted policy if you collect personal information from California residents.

**Fix:** Publish a plain-language privacy policy, link it from the footer, and add a cookie consent tool if you later add analytics or marketing scripts. Because only the home page was scanned, confirm whether other pages collect data.

### 2.6 Accessibility: **Low**
The real-browser automated test (axe-core) found **0 violations**, with 9 rules passed and 1 item flagged for manual review. Keyboard navigation reached the single focusable element, with no keyboard trap detected. The static HTML check found two minor issues:

1. **No `<h1>` main heading** (WCAG 1.3.1 / 2.4.6). Screen-reader users rely on headings to understand the page.
   **Fix:** Add one clear `<h1>` stating what the page or business is.
2. **No "skip to content" link** (WCAG 2.4.1). This matters mainly on pages with repeated menus, so it is a low concern on a page this small, but it will matter as the site grows.
   **Fix:** Add a skip link as the first focusable element once navigation exists.

**Standards touched:** ADA / WCAG 2.1 AA. Automated tools catch only part of the issues, so a manual review (colour contrast, screen-reader use) is still recommended. The scan also flagged one item for manual review that it could not resolve automatically.

### 2.7 TLS certificate expires in 38 days: **Low**
**What we saw:** TLS 1.3 is in use, which is the current best standard. The certificate was issued through Cloudflare and expires on **25 December 2026**.

**What it means:** Cloudflare-managed certificates normally renew automatically, so this is likely routine. An expired certificate would show visitors a full-page security warning.

**Standards touched:** PCI-DSS and breach laws (indirectly, via availability and trust).

**Fix:** Confirm auto-renewal is active in Cloudflare and that someone receives the expiry notices.

### 2.8 No robots.txt file: **Low (informational)**
No `robots.txt` was found. This is not a security problem. It only means search engines get no crawl guidance. Add one if you want to control what is indexed.

---

## 3. Positive Findings

- **TLS 1.3** is in use, the strongest current encryption version.
- **Email anti-spoofing is strong.** The SPF record (`v=spf1 -all`) says no servers are authorized to send email for this domain, and DMARC is set to `p=reject` with strict alignment. This makes it very hard for criminals to forge email from your domain.
  - **Caveat:** If you *do* send email from `@example.com` (staff, newsletters, invoices), this SPF setting would cause legitimate mail to be rejected or flagged. Confirm with whoever manages your email that the domain is meant to be "no-send."
  - **DKIM was not checked.** It uses organization-specific selectors, so ask your mail administrator to verify it.
- **No analytics or trackers** were detected, which reduces privacy-compliance exposure.
- **No image accessibility problems** and no automated browser accessibility violations.

---

## 4. Not Checked / Limitations

- **Only the home page was assessed.** The crawl discovered 0 additional pages, so other pages, forms, login areas, and checkout flows were not reviewed.
- Cookie attributes, form security, third-party scripts on other pages, and server vulnerabilities were not tested.
- Colour contrast and screen-reader behavior were not fully tested.
- DKIM was not verified.
- This passive scan **does not** establish that the site is secure or compliant. It indicates areas of concern based on publicly visible information.

---

## 5. Prioritized Action List

1. **Turn on "Always Use HTTPS"** in Cloudflare so the HTTP version redirects to HTTPS (Finding 2.1).
2. **Enable HSTS** once the redirect works (Finding 2.2).
3. **Add a Content-Security-Policy**, starting in report-only mode (Finding 2.3).
4. **Publish a privacy policy** and link it in the footer. Add cookie consent if you add analytics or marketing tools (Finding 2.5).
5. **Add the four remaining security headers** (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) in one configuration change (Finding 2.4).

**Quick follow-ups:**
- Add an `<h1>` heading and, as the site grows, a skip link (2.6).
- Confirm certificate auto-renewal (2.7).
- Confirm with your mail administrator that the "no-send" SPF setting matches how you use email, and have DKIM verified.
- If the site has more pages than the home page, request a full scan so forms, payments, and personal-data collection can be assessed.