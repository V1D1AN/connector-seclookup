"""SecLookup API client."""

import logging

import requests

logger = logging.getLogger("SecLookup")


class SecLookupAPIError(Exception):
    """Raised when the SecLookup API returns an unexpected response."""

    def __init__(self, status_code: int, url: str, body: str):
        self.status_code = status_code
        self.url = url
        self.body = body
        super().__init__(
            f"SecLookup API error: HTTP {status_code} from {url} — "
            f"body (first 500 chars): {body[:500]}"
        )


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
    # Shared response handler
    # ------------------------------------------------------------------
    def _parse_response(self, resp: requests.Response) -> dict:
        """Validate HTTP status and parse JSON, with clear error messages."""
        url = resp.url
        status = resp.status_code
        body = resp.text

        logger.info(
            "[SecLookup] %s %s → HTTP %d (%d bytes)",
            resp.request.method,
            url,
            status,
            len(body),
        )

        # HTTP error (4xx / 5xx)
        if not resp.ok:
            raise SecLookupAPIError(status, url, body)

        # Empty body (200 but nothing returned)
        if not body or not body.strip():
            raise SecLookupAPIError(
                status, url, "<empty response body>"
            )

        # Attempt JSON parse
        try:
            return resp.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            raise SecLookupAPIError(status, url, body)

    # ------------------------------------------------------------------
    # Domain lookup  –  GET /v1/domain/{domain}
    # ------------------------------------------------------------------
    def lookup_domain(self, domain: str) -> dict:
        """Query domain intelligence."""
        resp = self.session.get(
            f"{self.api_url}/domain/{domain}", timeout=30
        )
        return self._parse_response(resp)

    # ------------------------------------------------------------------
    # IP lookup  –  GET /v1/ip/{ip}   (inferred endpoint pattern)
    # ------------------------------------------------------------------
    def lookup_ip(self, ip: str) -> dict:
        """Query IP intelligence."""
        resp = self.session.get(
            f"{self.api_url}/ip/{ip}", timeout=30
        )
        return self._parse_response(resp)

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
        return self._parse_response(resp)