"""OpenCTI SecLookup enrichment connector."""

import os
import sys
import traceback

import stix2
from pycti import OpenCTIConnectorHelper, get_config_variable

from .seclookup_client import SecLookupClient


# TLP ordering for max-TLP filtering
TLP_ORDER = {
    "TLP:CLEAR": 0,
    "TLP:WHITE": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}


class SecLookupConnector:
    """Enrichment connector that queries SecLookup for Domain, IP, and URL observables."""

    def __init__(self):
        config = {}

        self.helper = OpenCTIConnectorHelper(config)

        # --- SecLookup settings ---
        self.api_key = get_config_variable(
            "SECLOOKUP_API_KEY", ["seclookup", "api_key"], config
        )
        self.api_url = get_config_variable(
            "SECLOOKUP_API_URL",
            ["seclookup", "api_url"],
            config,
            default="https://api.seclookup.com/v1",
        )
        self.score_threshold = int(
            get_config_variable(
                "SECLOOKUP_SCORE_THRESHOLD",
                ["seclookup", "score_threshold"],
                config,
                default="50",
            )
        )
        self.max_tlp = get_config_variable(
            "SECLOOKUP_MAX_TLP",
            ["seclookup", "max_tlp"],
            config,
            default="TLP:AMBER",
        )

        self.client = SecLookupClient(self.api_url, self.api_key)

        self.helper.log_info("[SecLookup] Connector initialised.")

    # ------------------------------------------------------------------
    # TLP check
    # ------------------------------------------------------------------
    def _is_tlp_allowed(self, entity: dict) -> bool:
        """Return True if entity TLP is at or below max_tlp."""
        markings = entity.get("objectMarking", [])
        for marking in markings:
            definition = marking.get("definition", "").upper()
            if definition.startswith("TLP:"):
                if TLP_ORDER.get(definition, 99) > TLP_ORDER.get(
                    self.max_tlp.upper(), 2
                ):
                    return False
        return True

    # ------------------------------------------------------------------
    # STIX bundle helpers
    # ------------------------------------------------------------------
    def _build_external_reference(self, observable_value: str) -> stix2.ExternalReference:
        return stix2.ExternalReference(
            source_name="SecLookup",
            url=f"https://app.seclookup.com/lookup/{observable_value}",
            description="SecLookup threat intelligence report",
        )

    def _risk_to_score(self, risk_score: int) -> int:
        """Map SecLookup risk_score (0-100) to OpenCTI score (0-100)."""
        return min(max(risk_score, 0), 100)

    def _threats_to_labels(self, threats: list[str]) -> list[str]:
        """Normalise threat tags into OpenCTI labels."""
        return [t.strip().lower() for t in threats if t and t.strip()]

    # ------------------------------------------------------------------
    # Enrichment logic per observable type
    # ------------------------------------------------------------------
    def _enrich_domain(self, entity: dict) -> list:
        value = entity.get("value", entity.get("observable_value", ""))
        self.helper.log_info(f"[SecLookup] Enriching domain: {value}")

        data = self.client.lookup_domain(value)
        return self._process_response(entity, data, value, "Domain-Name")

    def _enrich_ipv4(self, entity: dict) -> list:
        value = entity.get("value", entity.get("observable_value", ""))
        self.helper.log_info(f"[SecLookup] Enriching IP: {value}")

        data = self.client.lookup_ip(value)
        return self._process_response(entity, data, value, "IPv4-Addr")

    def _enrich_url(self, entity: dict) -> list:
        value = entity.get("value", entity.get("observable_value", ""))
        self.helper.log_info(f"[SecLookup] Enriching URL: {value}")

        data = self.client.lookup_url(value)
        return self._process_response(entity, data, value, "Url")

    # ------------------------------------------------------------------
    # Common response → STIX processing
    # ------------------------------------------------------------------
    def _process_response(
        self, entity: dict, data: dict, value: str, observable_type: str
    ) -> list:
        """Convert a SecLookup API response into STIX objects + OpenCTI updates."""
        stix_objects = []
        risk_score = data.get("risk_score", 0)
        threats = data.get("threats", [])
        opencti_score = self._risk_to_score(risk_score)

        # --- Update observable score ---
        self.helper.api.stix_cyber_observable.update_field(
            id=entity["id"],
            input={"key": "x_opencti_score", "value": str(opencti_score)},
        )

        # --- Add labels from threats ---
        for label_name in self._threats_to_labels(threats):
            label = self.helper.api.label.read_or_create_unchecked(
                value=label_name, color="#ff5722"
            )
            if label:
                self.helper.api.stix_cyber_observable.add_label(
                    id=entity["id"], label_id=label["id"]
                )

        # --- Add external reference ---
        ext_ref = self._build_external_reference(value)
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=entity["id"],
            external_reference_id=self.helper.api.external_reference.create(
                source_name=ext_ref.source_name,
                url=ext_ref.url,
                description=ext_ref.description,
            )["id"],
        )

        # --- DNS-resolved IPs → create IPv4 observables + relationship ---
        dns_data = data.get("dns", {})
        a_records = dns_data.get("a", [])
        for ip in a_records:
            if ip and ip != value:
                # Create the resolved IP observable
                ip_observable = self.helper.api.stix_cyber_observable.create(
                    observableData={
                        "type": "ipv4-addr",
                        "value": ip,
                    }
                )
                if ip_observable:
                    # Create resolves-to relationship
                    relationship = stix2.Relationship(
                        id=f"relationship--{self.helper.api.stix2.generate_id()}",
                        relationship_type="resolves-to",
                        source_ref=entity["standard_id"],
                        target_ref=ip_observable["standard_id"],
                        created_by_ref=self.helper.connect_identity,
                        allow_custom=True,
                    )
                    stix_objects.append(relationship)

        # --- SSL info as note ---
        ssl_data = data.get("ssl", {})
        if ssl_data:
            ssl_valid = ssl_data.get("valid", None)
            ssl_summary = f"**SecLookup SSL Analysis for `{value}`**\n\n"
            ssl_summary += f"- Certificate valid: `{ssl_valid}`\n"
            for k, v in ssl_data.items():
                if k != "valid":
                    ssl_summary += f"- {k}: `{v}`\n"

            note = stix2.Note(
                abstract=f"SecLookup SSL analysis – {value}",
                content=ssl_summary,
                created_by_ref=self.helper.connect_identity,
                object_refs=[entity["standard_id"]],
                allow_custom=True,
            )
            stix_objects.append(note)

        # --- WHOIS info as note ---
        whois_data = data.get("whois", {})
        if whois_data:
            whois_summary = f"**SecLookup WHOIS for `{value}`**\n\n"
            for k, v in whois_data.items():
                whois_summary += f"- {k}: `{v}`\n"

            note = stix2.Note(
                abstract=f"SecLookup WHOIS – {value}",
                content=whois_summary,
                created_by_ref=self.helper.connect_identity,
                object_refs=[entity["standard_id"]],
                allow_custom=True,
            )
            stix_objects.append(note)

        # --- If score ≥ threshold → create Indicator ---
        if opencti_score >= self.score_threshold:
            pattern = self._build_stix_pattern(observable_type, value)
            indicator = stix2.Indicator(
                name=f"SecLookup – {value}",
                description=(
                    f"Auto-generated indicator from SecLookup enrichment. "
                    f"Risk score: {risk_score}/100. Threats: {', '.join(threats)}."
                ),
                pattern=pattern,
                pattern_type="stix",
                valid_from=self.helper.api.stix2.now(),
                created_by_ref=self.helper.connect_identity,
                external_references=[ext_ref],
                custom_properties={
                    "x_opencti_score": opencti_score,
                    "x_opencti_main_observable_type": observable_type,
                },
                allow_custom=True,
            )
            stix_objects.append(indicator)

            # based-on relationship  Indicator → Observable
            rel = stix2.Relationship(
                relationship_type="based-on",
                source_ref=indicator.id,
                target_ref=entity["standard_id"],
                created_by_ref=self.helper.connect_identity,
                allow_custom=True,
            )
            stix_objects.append(rel)

        return stix_objects

    # ------------------------------------------------------------------
    # Pattern builder
    # ------------------------------------------------------------------
    @staticmethod
    def _build_stix_pattern(obs_type: str, value: str) -> str:
        escaped = value.replace("'", "\\'")
        mapping = {
            "Domain-Name": f"[domain-name:value = '{escaped}']",
            "IPv4-Addr": f"[ipv4-addr:value = '{escaped}']",
            "Url": f"[url:value = '{escaped}']",
        }
        return mapping.get(obs_type, f"[domain-name:value = '{escaped}']")

    # ------------------------------------------------------------------
    # Main callback
    # ------------------------------------------------------------------
    def _process_message(self, data: dict) -> str:
        entity_id = data["entity_id"]
        self.helper.log_info(f"[SecLookup] Processing entity {entity_id}")

        entity = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if entity is None:
            return "Observable not found"

        # TLP check
        if not self._is_tlp_allowed(entity):
            self.helper.log_info(
                f"[SecLookup] Skipping {entity_id} – TLP above {self.max_tlp}"
            )
            return "TLP too high, skipping"

        entity_type = entity.get("entity_type", "")
        stix_objects = []

        try:
            if entity_type == "Domain-Name":
                stix_objects = self._enrich_domain(entity)
            elif entity_type in ("IPv4-Addr", "IPv6-Addr"):
                stix_objects = self._enrich_ipv4(entity)
            elif entity_type == "Url":
                stix_objects = self._enrich_url(entity)
            else:
                return f"Unsupported entity type: {entity_type}"
        except Exception as e:
            self.helper.log_error(f"[SecLookup] API error: {e}")
            self.helper.log_error(traceback.format_exc())
            return f"SecLookup API error: {e}"

        # Send STIX bundle if we have objects
        if stix_objects:
            bundle = stix2.Bundle(
                objects=stix_objects,
                allow_custom=True,
            )
            self.helper.send_stix2_bundle(bundle.serialize())

        return (
            f"SecLookup enrichment completed for {entity_type} "
            f"({len(stix_objects)} STIX objects)"
        )

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        connector = SecLookupConnector()
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
