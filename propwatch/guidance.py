"""
Fixed, human-written "what this usually means" notes. No AI, no guessing.

Sources (city pages; the notice on an actual violation always controls):
  HPD class timelines: NYC DHS shelter category definitions (A: 90 days to
    correct, B: 30 days, C: 24 hours; certify repair within about 2 weeks /
    2 weeks / 5 days)
  DOB/ECB: nyc.gov/site/buildings/property-or-business-owner/certificate-of-correction.page
           nyc.gov/assets/oath/downloads/pdf/Cure.pdf
Penalty dollar amounts are deliberately left out until confirmed with HPD/DOB.
"""

LINKS = {
    "dob_coc": "https://www.nyc.gov/site/buildings/property-or-business-owner/certificate-of-correction.page",
    "oath_cure": "https://www.nyc.gov/assets/oath/downloads/pdf/Cure.pdf",
}


def next_steps(r: dict) -> list:
    """List of {'title','body','link'} for a lookup() result. Empty if nothing is open."""
    steps = []
    h = r["hpd"]["open_by_class"]
    dob_n = r["dob"]["active_older_system"] + r["dob"]["active_dob_now"]
    ecb = r["ecb_penalties"]

    if h.get("C"):
        steps.append({
            "title": f"{h['C']} Class C (immediately hazardous) housing violation"
                     f"{'s' if h['C'] != 1 else ''}",
            "body": "HPD gives owners 24 hours to correct a Class C violation and about "
                    "5 days to certify the repair. Anything still open on an old notice is "
                    "well past that. Fix the condition first, then certify the correction "
                    "with HPD. Some types (such as lead paint) follow different timelines; "
                    "the notice states the date.",
            "link": None})
    if h.get("B"):
        steps.append({
            "title": f"{h['B']} Class B (hazardous) housing violation{'s' if h['B'] != 1 else ''}",
            "body": "Owners get 30 days to correct a Class B violation and about 2 weeks to "
                    "certify the repair.", "link": None})
    if h.get("A"):
        steps.append({
            "title": f"{h['A']} Class A (non-hazardous) housing violation{'s' if h['A'] != 1 else ''}",
            "body": "Owners get 90 days to correct a Class A violation and about 2 weeks to "
                    "certify the repair. Limited extra time can sometimes be requested "
                    "before the deadline passes; ask HPD.", "link": None})
    if sum(h.values()):
        steps.append({
            "title": "Fixing it is not enough; it has to be certified",
            "body": "A violation stays open in city records until the correction is "
                    "certified or the city closes it. If a repair was made but never "
                    "certified, the item can still show as open. Check each open item "
                    "on HPD Online.", "link": None})
    if dob_n:
        steps.append({
            "title": f"{dob_n} active Department of Buildings violation{'s' if dob_n != 1 else ''}",
            "body": "These often come with a hearing at OATH. Choosing to cure means "
                    "admitting the violation; the alternative is to attend the hearing. "
                    "Missing the hearing means the maximum penalty. Even after paying, a "
                    "violation can stay open until a certificate of correction is filed "
                    "(filed in DOB NOW: Safety since Dec 15, 2025).",
            "link": LINKS["dob_coc"]})
    if ecb["active"]:
        steps.append({
            "title": f"{ecb['active']} active penalty case{'s' if ecb['active'] != 1 else ''}",
            "body": "Filing an acceptable certificate of correction before the first "
                    "hearing date can stop daily penalties on some summonses.",
            "link": LINKS["oath_cure"]})
    if steps:
        steps.append({
            "title": "Before you act",
            "body": "This is general information, not legal advice. The notice on each "
                    "violation sets its own deadline. Consider a licensed professional "
                    "for hazardous conditions.", "link": None})
    return steps
