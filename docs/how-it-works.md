# How Propwatch works

Propwatch shows what New York City already has on record for a property, in
one place and in plain English.

## Where the information comes from
All of it comes from the city's own public data. Nothing is scraped, bought
or estimated, and no login is used.

| What | Source |
|---|---|
| Address to property ID | NYC Planning address lookup (free, public) |
| Housing violations | HPD housing maintenance code violations, NYC Open Data |
| Building violations | Department of Buildings violations, older and newer systems, NYC Open Data |
| Penalties | ECB / OATH penalties, NYC Open Data |
| Building complaints | Department of Buildings complaints, NYC Open Data |
| 311 requests | NYC 311 service requests, NYC Open Data |

## What happens when you look up an address
1. The address is sent to NYC Planning, which returns the property's tax-lot
   and building ID.
2. Those IDs are used to ask the city's data service about that property.
3. The results are counted and written up.

## What Propwatch does to the data
- Keeps only what is still **open or active**, and leaves out closed and
  dismissed records.
- **Counts** records and groups housing violations by hazard class:
  Class C is immediately hazardous, Class B is hazardous, Class A is
  non-hazardous.
- **Adds up** penalty balances and finds the oldest open item.
- **Shortens** long violation descriptions.
- Writes sentences from **fixed templates**.

It does not use artificial intelligence, add opinions, estimate, or fill in
gaps. If the city has no record, Propwatch shows none.

## What it cannot tell you
- It reports what is **on record**. It does not say a building is safe or
  unsafe, or that an owner is compliant.
- City records can lag or contain errors. Some old items marked open may be
  paperwork that was never closed.
- Housing records mostly cover multi-unit rentals. Many 1-2 family homes show
  nothing there.
- It is not legal advice and does not replace a licensed inspector.

## Privacy
Addresses you search are sent to the city's public services to get results.
The app on your computer does not keep a record of searches.

## Check our work
Compare any result with the city's own sites (HPD Online and the Department of
Buildings property search). If they differ, the city's site is the source of
truth, and please tell us.
