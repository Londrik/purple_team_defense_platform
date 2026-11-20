# ADR-002: Canonical ECS 8.x Normalization and MITRE ATT&CK v14+ Tagging

- **Status:** Accepted
- **Context:** Raw application and HTTP logs vary in structure, making SIEM correlation, rule portability, and incident reporting brittle across detection scenarios.
- **Decision:** Normalize ingested events to Elastic Common Schema (ECS 8.x) (`source.ip`, `http.request.method`, `url.path`, `threat.tactic.id`, `threat.technique.id`) and map attack vectors explicitly to MITRE ATT&CK tactics and techniques (`T1190`, `T1083`, `T1189`, `T1068`).
- **Consequences:**
  - Standardizes query fields across Kibana detection rules, audit logs, and documentation.
  - Adds schema validation overhead in the ingest pipeline and requires keeping rule definitions synchronized with ECS fields.
- **Rejected Alternatives:**
  - Indexing unparsed raw log strings with ad-hoc custom field names (low correlation fidelity and poor reusability).
