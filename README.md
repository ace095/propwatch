# Propwatch

Plain-English violation alerts for NYC property owners.

Small landlords and co-op boards often learn about housing and building
violations late, after fines have grown. Propwatch reads the city's public
data for an address and tells the owner what is on record, what is new, and
what to do about it.

> Status: early prototype. It looks up **one address** today. Weekly email
> digests are next.

## What it does today
Looks up open violations for an address from NYC Open Data (public Socrata
datasets):

| Dataset | ID |
|---|---|
| HPD housing maintenance code violations | `wvxf-dwi5` |
| DOB violations (older, BIS) | `3h2n-5cm9` |
| DOB safety violations (newer, DOB NOW) | `855j-jady` |

```bash
python -m propwatch 22 "Stagg Street" brooklyn
python -m propwatch 22 "Stagg Street" brooklyn --json out.json
```

Output: open HPD violations (with Class A/B/C counts; **C = immediately
hazardous**), oldest open issue date, and active DOB violations.

## Limits (be honest about these)
- Matches by house number + street text, not a geocoder, so unusual spellings
  or corner buildings can miss.
- Reports what is **on record**. It says nothing about whether a building is
  structurally safe; that takes a licensed professional.
- Not yet checked against the city's own lookup tools for accuracy.

## Roadmap
1. Address list + weekly diff ("2 new violations since last week")
2. Claude-written plain-English summary and next steps for each violation
3. Email digest
4. Filing/inspection deadline reminders (e.g. facade, boiler)
5. Validate demand with landlords / co-op boards before building more

## Setup
```bash
pip install -r requirements.txt
cp .env.example .env     # only needed for the Claude summaries (coming next)
python -m unittest discover -s tests -v
```

## Principles
- Public data only; no scraping behind logins.
- Say "on record" / "indicates", never "safe" or "compliant".
