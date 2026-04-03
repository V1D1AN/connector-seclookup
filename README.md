# OpenCTI – SecLookup Enrichment Connector

Connecteur d'enrichissement interne pour [SecLookup](https://www.seclookup.com/), une plateforme de threat intelligence temps réel.

## Fonctionnalités

| Observable   | Endpoint SecLookup          | Données enrichies                                      |
|------------- |---------------------------- |-------------------------------------------------------|
| Domain-Name  | `GET /v1/domain/{domain}`   | Risk score, threats, DNS (A records), SSL, WHOIS       |
| IPv4-Addr    | `GET /v1/ip/{ip}`           | Risk score, threats                                    |
| Url          | `POST /v1/url/lookup`       | Risk score, threats                                    |

### Ce que fait le connecteur

- Met à jour le **score OpenCTI** (`x_opencti_score`) à partir du `risk_score` SecLookup
- Ajoute des **labels** issus des `threats` retournées (phishing, malware, etc.)
- Crée une **external reference** vers SecLookup
- Crée des **observables IPv4** résolus + relations `resolves-to` (DNS A records)
- Génère des **Notes STIX** pour les données SSL et WHOIS
- Crée un **Indicator STIX** + relation `based-on` si le score ≥ seuil configurable

### Filtrage

- **Max TLP** : ne traite pas les observables au-dessus du TLP configuré (défaut : `TLP:AMBER`)
- **Score threshold** : ne crée un Indicator que si `risk_score ≥ SECLOOKUP_SCORE_THRESHOLD`

## Installation

```bash
cp .env.sample .env
# Éditer .env avec vos tokens
docker compose up -d
```

## Configuration

| Variable                     | Défaut                           | Description                            |
|----------------------------- |--------------------------------- |----------------------------------------|
| `OPENCTI_URL`                | —                                | URL de l'instance OpenCTI              |
| `OPENCTI_TOKEN`              | —                                | Token API OpenCTI                      |
| `CONNECTOR_ID`               | —                                | UUID unique du connecteur              |
| `SECLOOKUP_API_KEY`          | —                                | Clé API SecLookup (Bearer token)       |
| `SECLOOKUP_API_URL`          | `https://api.seclookup.com/v1`   | Base URL de l'API                      |
| `SECLOOKUP_SCORE_THRESHOLD`  | `50`                             | Seuil pour création d'Indicator        |
| `SECLOOKUP_MAX_TLP`          | `TLP:AMBER`                      | TLP max autorisé pour l'enrichissement |

## Compatibilité

- OpenCTI **6.x** (pycti `>=6.0.0,<7.0.0`)
- Python **3.11+**

## ⚠️ Endpoints IP et URL

Les endpoints `/v1/ip/{ip}` et `/v1/url/lookup` sont **inférés** depuis le pattern de l'API domain.
Vérifiez dans la documentation SecLookup que ces endpoints existent ou adaptez `seclookup_client.py`.
