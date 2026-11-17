"""Turn "we could not check this" into a reason and a next step the client can act on."""

BLOCKED_STATUSES = (401, 403, 429)

REASONS = {
    "dns": (
        "The domain name could not be looked up.",
        "Check the domain is spelled correctly and its DNS records are working, then ask us to re-run the scan."),
    "timeout": (
        "The site did not answer in time.",
        "Check the site is online and not overloaded, then re-run. If it is slow by design, ask us to raise the wait time."),
    "connection": (
        "The connection was refused or dropped.",
        "A firewall may be blocking our scanner. Ask your web host to allow requests from the scanning computer during the scan, then re-run."),
    "tls": (
        "The secure connection could not be set up.",
        "This is likely a real certificate or encryption problem on the site. Fix the certificate (see the encryption finding), then re-run."),
    "blocked": (
        "The site refused our scanner (an access-denied, rate-limit or bot-check response).",
        "Ask your web host or security provider (for example Cloudflare) to allow our scanner and its 'WebAuditBot' user agent during the scan, then re-run. We do not try to get around bot protection."),
    "server_error": (
        "The site reported an error of its own.",
        "Check the site is working for visitors, then re-run."),
    "missing_tool": (
        "A tool this check needs is not installed on the scanning computer.",
        "This is a limit of our setup, not a problem with your site. We will fix it and re-run."),
    "unknown_error": (
        "The check failed for a reason we could not classify.",
        "Re-run the scan. If it keeps failing, send us the log and we will investigate."),
}

_PATTERNS = (
    ("dns", ("getaddrinfo", "name or service not known", "nodename nor servname", "nxdomain",
             "no address associated", "err_name_not_resolved")),
    ("timeout", ("timed out", "timeout")),
    ("tls", ("certificate", "ssl:", "tlsv1", "handshake", "err_cert", "err_ssl")),
    ("missing_tool", ("no usable edge or chrome", "executable doesn't exist")),
    ("connection", ("refused", "reset", "closed connection", "aborted", "10061", "10054", "unreachable",
                    "broken pipe", "err_connection")),
)


def classify(error: str = "", status: int = None) -> str:
    """Name the most likely reason a request failed."""
    if status in BLOCKED_STATUSES:
        return "blocked"
    if status is not None and status >= 500:
        return "server_error"
    text = (error or "").lower()
    for reason, needles in _PATTERNS:
        if any(n in text for n in needles):
            return reason
    return "unknown_error"


def unavailable(message: str, reason: str) -> dict:
    """The standard 'could not check' result. Keeps _unavailable, which everything else keys on."""
    why, action = REASONS[reason]
    return {"_unavailable": message, "reason": reason, "why": why, "client_action": action}
