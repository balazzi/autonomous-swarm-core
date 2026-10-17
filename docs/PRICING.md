# Pricing — Autonomous Swarm Core

Benchmarked Oct 2026 against the mobile security/utility cluster
(1Password Individual $2.99–3.99/mo, NordVPN from $3.49/mo).
Positioned at the top of the band: niche autonomous-security tooling,
zero-dependency, on-device PQC.

| Tier | Price (USD) | Store type | Agents | Notes |
|------|-------------|------------|--------|-------|
| Freemium | $0 | — | 5 | Permanent baseline; core telemetry + self-heal |
| Pro Monthly | $4.99/mo | auto-renewable subscription | 15 | Full lattice + TDA ransomware matrix |
| Pro Yearly | $39.99/yr (~$3.33/mo) | auto-renewable subscription | 15 | ~33% discount vs monthly; the default nudge |
| Lifetime | $99.99 one-time | non-consumable IAP | 15 | Price anchor; ≈2.5 yrs of yearly |

## Product IDs

Use identical IDs on App Store Connect and Google Play.
`PREFIX` = your app's reverse-DNS bundle ID (placeholder below: `com.balazzi.swarmcore`
— replace with the real bundle ID when the store listings are created).

- `com.balazzi.swarmcore.pro.monthly`
- `com.balazzi.swarmcore.pro.yearly`
- `com.balazzi.swarmcore.pro.lifetime`

## Code mapping

`src/billing.rs` currently gates two tiers: `FreemiumPermanent` (0) and
`ProSubscription` (1). All three paid products map to tier 1 — the host app
sets tier=1 after validating any of the three receipts. No Rust changes needed
unless a mid-tier is introduced later.

## Store notes

- Apple: monthly/yearly must be configured as an auto-renewable subscription
  group; lifetime as a separate non-consumable IAP.
- Google Play: monthly/yearly as subscriptions; lifetime as a one-time in-app
  product.
- Both stores take 15–30% depending on tenure/program.
