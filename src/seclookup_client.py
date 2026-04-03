"""SecLookup API client."""

import requests


class SecLookupClient:
    """Thin wrapper around the SecLookup REST API."""

    def __init__(self, api_url: str, api_key: str, verify_ssl: bool = True):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        self.session.verify = verify_ssl

    # ------------------------------------------------------------------
    # Domain lookup  –  GET /v1/domain/{domain}
    # ------------------------------------------------------------------
    def lookup_domain(self, domain: str) -> dict:
        """Query domain intelligence."""
        resp = self.session.get(f"{self.api_url}/domain/{domain}", timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # IP lookup  –  GET /v1/ip/{ip}   (inferred endpoint pattern)
    # ------------------------------------------------------------------
    def lookup_ip(self, ip: str) -> dict:
        """Query IP intelligence."""
        resp = self.session.get(f"{self.api_url}/ip/{ip}", timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # URL lookup  –  POST /v1/url/lookup  (inferred endpoint pattern)
    # ------------------------------------------------------------------
    def lookup_url(self, url: str) -> dict:
        """Query URL intelligence."""
        resp = self.session.post(
            f"{self.api_url}/url/lookup",
            json={"url": url},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
