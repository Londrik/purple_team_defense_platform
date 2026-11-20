# Project C — Purple Team SOAR, SIEM & Detection Engineering

[![CI Status](https://img.shields.io/badge/CI-GitHub%20Actions-blue)](#)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)](#)
[![Schema](https://img.shields.io/badge/ECS-8.x-005571)](#)
[![Framework](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%2B-red)](#)

## Architectural Abstract

Project C is a closed-loop Purple Team defensive engineering lab built on Fedora Linux. It combines adversary traffic emulation against OWASP Juice Shop, container log harvesting with Filebeat, Elastic Common Schema (ECS 8.x) ingestion normalization in Elasticsearch, MITRE ATT&CK v14+ correlation rules in Kibana Detection Engine, and an automated Python FastAPI SOAR service that enforces host-level containment through Linux Netfilter (`iptables` `PURPLE_JAIL` chain).

## Closed-Loop Defensive Flow

1. **Adversary Emulation:** Simulated attack payloads target the OWASP Juice Shop runtime (`:3000`).
2. **Telemetry Harvesting:** Filebeat collects container stdout/stderr streams using SELinux-compatible mounts (`:z`).
3. **ECS Normalization:** An Elasticsearch ingest pipeline parses raw HTTP/application logs into canonical ECS 8.x fields (`source.ip`, `http.request.method`, `url.path`, `threat.tactic.id`, `threat.technique.id`).
4. **Detection & Webhook Triggering:** Kibana Detection Engine evaluates correlation rules tagged with MITRE ATT&CK tactics/techniques and dispatches authenticated webhook alerts.
5. **Automated SOAR Containment:** A FastAPI receiver validates `X-SOAR-Token`, checks IP safelists, applies `iptables` drop rules inside `PURPLE_JAIL`, and writes structured audit records to `/var/log/soar_containment.json`.

## System Prerequisites

- **Host OS:** Fedora Linux with SELinux in `Enforcing` mode and `CAP_NET_ADMIN` for host firewall manipulation.
- **Container Runtime:** Docker Engine and Docker Compose plugin.
- **Python Runtime:** Python 3.11+ (`venv`, `ruff`, `bandit`, `pytest`, `mypy`).

## C4 Container Diagram

~~~mermaid
flowchart TD
    red["Red Team Emulation Scripts"] -->|"HTTP Attack Payloads"| juice["OWASP Juice Shop Container (:3000)"]
    juice -->|"Container stdout/stderr"| fb["Filebeat (:z volume)"]
    fb -->|"Raw Log Stream"| es["Elasticsearch Ingest & ECS 8.x Store"]
    es -->|"Indexed ECS Events"| kibana["Kibana Detection Engine (MITRE ATT&CK)"]
    kibana -->|"POST Webhook + X-SOAR-Token"| soar["FastAPI SOAR Service"]
    soar -->|"iptables -I PURPLE_JAIL"| netfilter["Linux Netfilter / iptables"]
    soar -->|"Append JSON Audit Log"| audit["/var/log/soar_containment.json"]
~~~
