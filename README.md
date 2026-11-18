# Propwatch

Plain-English violation alerts for NYC property owners.

Small landlords and co-op boards often learn about housing and building
violations late, after fines have grown. Propwatch reads the city's public
data for an address and tells the owner what is on record, what is new, and
what to do about it.

> Status: early prototype. Looks up **one address** at a time.

## How it works (3 steps)
```
type an address  ->  find its property ID  ->  ask the city's public datasets  ->  plain-English summary
```
1. **Address -> ID.** NYC Planning's free lookup turns "22 Stagg Street, Brooklyn" into the property's BBL/BIN.
2. **Ask six datasets** by that ID: HPD housing violations, DOB violations (old and new systems), ECB/OATH penalties, DOB complaints, and 311 requests (matched by address).
3. **Summarize** what is on record, with the hazard class and any money owed.

```bash
python -m propwatch "22 Stagg Street, Brooklyn"
python -m propwatch "22 Stagg Street, Brooklyn" --json out.json
```

Housing (HPD) records mostly cover multi-unit buildings. Private 1-2 family
homes usually show up in DOB, ECB and 311 instead, so the tool checks all of them.

## Why
Neglected buildings and unsafe conditions often go unseen, especially in
lower-income neighborhoods. The data is public but scattered across agencies.
Propwatch puts it in one place so owners, tenants and communities can see it,
and see what has gone unfixed for years.

## Limits (be honest about these)
- Needs a street address with a tax lot; intersections will not resolve.
- 311 matches by address text, so unusual spellings can miss.
- Reports what is **on record**. It says nothing about whether a building is
  structurally safe; that takes a licensed professional.
- Not yet checked against the city's own lookup tools for accuracy.

## Roadmap
1. Neighborhood view: rank zip codes / blocks by open hazardous violations and how long they have sat unfixed
2. Watch list + "what's new since last week"
3. Claude-written plain-English next steps per violation
4. Email digest
5. Validate demand (owners, tenants, community groups) before building more

## Setup
```bash
pip install -r requirements.txt
cp .env.example .env     # only needed for the Claude summaries (coming next)
python -m unittest discover -s tests -v
```

## Principles
- Public data only; no scraping behind logins.
- Say "on record" / "indicates", never "safe" or "compliant".
