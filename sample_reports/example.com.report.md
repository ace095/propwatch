# Website Security & Compliance Audit Report

**Website:** example.com
**Sector:** Small business
**Scan date:** 17 November 2026
**Scan type:** Passive (publicly visible information only)

> **Scope note:** This was a passive scan. It looked only at what the website shows publicly. It was not a penetration test, and it cannot confirm that the site is secure or vulnerable. Wording such as "indicates" and "suggests" reflects that limit.

---

## 1. Executive Summary

The site has a solid foundation: a modern encryption certificate (TLS 1.3) and a strict email anti-spoofing policy. The scan did find gaps in how the site enforces secure connections and in its browser protections. **The most important finding is that the unencrypted (http://) version of the site loads normally instead of redirecting visitors to the secure (https://) version.** Combined with the absence of all six standard security headers, this suggests visitors could be served over an unprotected connection.

No privacy policy or cookie notice was detected. That matters if the site collects any customer information.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 3 |
| Low | 4 |

---

## 2. What Looks Good

- **Modern encryption:** The site uses TLS 1.3, the current standard, with a certificate issued through Cloudflare.
- **Strict email spoofing protection:** The DMARC policy is set to `reject` with strict alignment, so fraudulent emails pretending to come from example.com should be refused by receiving mail servers.
- **Basic accessibility markers:** The page declares a language and has a title, both of which help screen-reader users.
- **No technology disclosure:** The site does not reveal the software it runs on (no "powered-by" header).

---

## 3. Findings

### 3.1 Insecure (HTTP) version of the site is not redirected to HTTPS: **HIGH**
**What we found:** Requesting the http:// address returned a normal page (status 200) with no redirect to https://. The scan found no evidence of a forced redirect.
**Plain English:** A visitor who types the address without "https://", or follows an old link, may land on an unencrypted page. Anything they send or view could be intercepted on public Wi-Fi, for example.
**Standards affected:**
- **PCI-DSS** (if you take card payments): requires strong encryption of cardholder data in transit.
- **State data-breach laws and CCPA/GDPR:** expect "reasonable security" for personal data. Unencrypted transmission weakens that position.

**Fix:** Turn on a site-wide permanent (301) redirect from HTTP to HTTPS. Since the site is behind Cloudflare, this is typically the "Always Use HTTPS" setting. Then retest.

---

### 3.2 HSTS header missing: **MEDIUM**
**What we found:** No `Strict-Transport-Security` header was present.
**Plain English:** HSTS tells browsers to *always* use the secure version of the site. Without it, browsers can be tricked into using the insecure version, especially on a first visit.
**Standards affected:** PCI-DSS (transport security), state breach laws, CCPA/GDPR (reasonable safeguards).
**Fix:** After the HTTPS redirect works, enable HSTS (for example `max-age=31536000; includeSubDomains`). Start with a shorter duration if unsure, since HSTS is hard to undo once browsers cache it.

---

### 3.3 No privacy policy or cookie notice detected: **MEDIUM**
**What we found:** No privacy policy page was found, and there were no mentions of cookies and no cookie banner. No analytics were detected.
**Plain English:** If the site collects any personal information (contact forms, newsletter signups, orders), visitors are generally entitled to know what you collect and why. Because no analytics or trackers were detected, a cookie banner may not be required today, but the absence of a policy still stands out.
**Standards affected:** **CCPA/GDPR** (notice at collection), plus state privacy laws. Payment processors also often require a published policy.
**Fix:** Publish a privacy policy that matches your actual data practices, and link it in the footer. Add a cookie banner only if you add analytics, ads, or other tracking later. *This scan did not check whether the site has forms or collects data, so confirm internally.*

---

### 3.4 Content-Security-Policy (CSP) missing: **MEDIUM**
**What we found:** No `Content-Security-Policy` header.
**Plain English:** CSP limits what scripts can run on your pages, which is a major defense against malicious code injection (such as skimming scripts on payment pages).
**Standards affected:** **PCI-DSS** (v4.0 requirements on controlling and monitoring scripts on payment pages), state breach laws.
**Fix:** Deploy a CSP, ideally in "report-only" mode first so nothing breaks. The risk is lower if the site is a simple static page with no forms or payments.

---

### 3.5 Other browser-protection headers missing: **LOW**
**What we found:** Missing `X-Frame-Options` (clickjacking protection), `X-Content-Type-Options` (MIME-sniffing protection), `Referrer-Policy` (limits information leaked to other sites), and `Permissions-Policy` (restricts browser features like camera and location).
**Plain English:** These are low-effort "hardening" settings. Each one closes off a small avenue of abuse.
**Standards affected:** General security best practice. Indirectly supports PCI-DSS and privacy obligations (CCPA/GDPR).
**Fix:** Add these headers at the Cloudflare or web-server level, for example `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and a restrictive `Permissions-Policy`.

---

### 3.6 Email configuration: SPF blocks all senders: **LOW (needs confirmation)**
**What we found:** SPF is `v=spf1 -all`, meaning *no* server is authorized to send mail for this domain. DMARC is set to `reject`. DKIM was not checked, because it needs the organization's mail selectors.
**Plain English:**
- **If this domain is not used for email,** this is an ideal configuration.
- **If your business sends email from @example.com** (staff mailboxes, invoices, newsletters), this setup would cause legitimate messages to be rejected or land in spam.

**Standards affected:** Data-breach and fraud prevention (phishing and spoofing protection).
**Fix:** Confirm with whoever manages your email. If the domain sends mail, update SPF to include your mail provider and verify DKIM. If it doesn't, no change is needed.

---

### 3.7 Certificate expires in 38 days: **LOW**
**What we found:** The certificate expires 25 December 2026 (38 days from the scan).
**Plain English:** This is not a problem if renewal is automatic. If renewal is manual, an expired certificate would show visitors a full-page security warning, likely over the holiday period.
**Fix:** Confirm automatic renewal is active, and set a calendar reminder as a backup.

---

### 3.8 No robots.txt file: **LOW (informational)**
**What we found:** No `robots.txt` was found.
**Plain English:** This file guides search engines on what to index. Its absence is not a security flaw, and it should not be used to hide sensitive content.
**Fix:** Optionally add one, for example to point to your sitemap.

---

## 4. Accessibility (ADA / WCAG 2.1 AA)

The basic checks passed: the page has a language attribute and a title, and no images were detected, so none are missing alt text. **This was only a minimal automated check.** It does not cover color contrast, keyboard navigation, form labels, or many other WCAG 2.1 AA requirements. Accessibility is a frequent subject of ADA-related claims against business websites. A full audit with a tool such as axe-core or Pa11y, plus manual testing, is recommended.

---

## 5. Not Checked / Limitations

- **DKIM:** requires the organization's mail selectors.
- **Whether the site collects data or takes payments:** not determined by this scan, so PCI-DSS and privacy relevance is conditional.
- **Full WCAG compliance:** only a basic check was run.
- **Server-side and application vulnerabilities:** outside the scope of a passive scan.
- **One data discrepancy:** the header check reported the HTTPS-redirect status as undetermined, while the dedicated redirect test showed no redirect. The report uses the dedicated test, and it is worth re-verifying after changes.

---

## 6. Prioritized Action List

1. **Force HTTP → HTTPS redirect site-wide** (High). In Cloudflare, enable "Always Use HTTPS" or add a 301 redirect rule.
2. **Enable HSTS** once the redirect is confirmed working (Medium).
3. **Publish a privacy policy** that reflects what the site actually collects, and link it in the footer (Medium).
4. **Deploy a Content-Security-Policy**, starting in report-only mode (Medium).
5. **Add the four remaining security headers:** X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy (Low, quick win).
6. **Confirm email intent:** make sure the "no senders allowed" SPF record matches how the domain is actually used, and verify DKIM if it sends mail.
7. **Verify certificate auto-renewal** before 25 December 2026.
8. **Commission a full accessibility audit** (WCAG 2.1 AA).

Once items 1 through 5 are done, a re-scan will confirm the changes took effect.