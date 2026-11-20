# Architecture Specification (Arc42) — Project C

## 1. Introduction and Goals

Project C implements an automated detection and response pipeline aligned with NIST SP 800-61 Rev. 2 (Detection & Analysis and Containment, Eradication & Recovery). The architecture validates detection fidelity and automated firewall isolation without manual operator intervention during high-severity attack waves.

## 2. Constraints and Context

- **Runtime Environment:** Fedora Linux host with SELinux (`Enforcing`) and Netfilter/`iptables` access.
- **Schema & Threat Standards:** Elastic Common Schema (ECS 8.x) and MITRE ATT&CK Enterprise Matrix v14+.
- **In Scope:** Attack traffic generation against Juice Shop, log parsing to ECS 8.x, rule correlation, webhook ingestion, safelist evaluation, `PURPLE_JAIL` rule insertion, and JSON audit logging.
- **Out of Scope:** Multi-region cloud orchestration, external commercial EDR agents, and automated kernel module replacement.

## 3. Runtime Sequence Flow

~~~mermaid
sequenceDiagram
    autonumber
    participant Attacker as Emulation Client
    participant Target as OWASP Juice Shop
    participant FB as Filebeat
    participant ES as Elasticsearch Pipeline
    participant KBN as Kibana Detection Engine
    participant SOAR as FastAPI SOAR Receiver
    participant IPT as Linux iptables (PURPLE_JAIL)

    Attacker->>Target: Send malicious HTTP payload
    Target-->>Attacker: Return HTTP response
    Target->>FB: Emit container stdout/stderr log
    FB->>ES: Forward log event
    ES->>ES: Normalize fields to ECS 8.x
    KBN->>ES: Query normalized events against MITRE rule
    KBN->>SOAR: POST /webhook/alert-action (X-SOAR-Token)
    SOAR->>SOAR: Verify token, severity, and IP safelist
    SOAR->>IPT: Insert DROP rule for attacker IP in PURPLE_JAIL
    SOAR->>SOAR: Append audit entry to /var/log/soar_containment.json
    SOAR-->>KBN: Return 200 OK containment status
~~~

## 4. Security Architecture and STRIDE Threat Model

| STRIDE Threat | Attack Vector in SOAR Loop | Architectural Control |
|---|---|---|
| **Spoofing** | Forged webhook POST requests pretending to be Kibana Alerting | Mandatory `X-SOAR-Token` header verification using constant-time comparison |
| **Tampering** | Modification of alert payloads or audit log tampering | Strict Pydantic payload validation and append-only `/var/log/soar_containment.json` audit trail |
| **Repudiation** | Denying automated block actions or missing incident context | Structured JSON audit log recording timestamp, rule ID, source IP, severity, and outcome |
| **Information Disclosure** | Leaking secrets or internal topology in webhook error responses | Generic authorization/validation responses without internal stack traces or secret values |
| **Denial of Service** | Self-DoS by blocking loopback, container bridge gateway, or internal management IPs | Safelist validation engine blocking containment for `127.0.0.1`, `172.18.0.1`, and RFC 1918 ranges |
| **Elevation of Privilege** | Abuse of `CAP_NET_ADMIN` or `iptables` execution to alter arbitrary firewall rules | Dedicated `PURPLE_JAIL` chain isolation and parameterized subprocess execution without shell interpolation |

## 5. Linux Netfilter / iptables Integration Model

- **Dedicated Chain Isolation:** All automated blocks are isolated inside the `PURPLE_JAIL` chain linked from `INPUT`, keeping host baseline firewall rules intact.
- **Safelist Guard:** Before invoking `iptables`, the service rejects loopback (`127.0.0.1`, `::1`), Docker bridge gateway (`172.18.0.1`), and private RFC 1918 management addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) unless explicitly overridden in configuration.
- **Audit Logging:** Every containment attempt writes a structured JSON event to `/var/log/soar_containment.json` (with SELinux context/volume labeling `:z` when mounted into containers).
