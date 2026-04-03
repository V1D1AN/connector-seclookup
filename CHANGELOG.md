# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-04-03

### Added
- Initial release
- Domain enrichment via SecLookup API (`GET /v1/domain/{domain}`)
- IPv4 enrichment via SecLookup API (`GET /v1/ip/{ip}`) — inferred endpoint
- URL enrichment via SecLookup API (`POST /v1/url/lookup`) — inferred endpoint
- OpenCTI score update from SecLookup `risk_score`
- Automatic label creation from SecLookup `threats` array
- DNS A record resolution → IPv4 observable creation + `resolves-to` relationship
- STIX Note creation for SSL and WHOIS data
- STIX Indicator creation + `based-on` relationship when score ≥ threshold
- External reference linking to SecLookup
- TLP max filtering (configurable, default `TLP:AMBER`)
- Score threshold for Indicator creation (configurable, default `50`)
- Docker Compose deployment
- pycti `>=6.0.0,<7.0.0` compatibility (OpenCTI 6.x)
