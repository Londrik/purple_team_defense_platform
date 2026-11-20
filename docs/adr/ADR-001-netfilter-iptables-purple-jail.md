# ADR-001: Host Containment via Dedicated Netfilter / iptables Chain (`PURPLE_JAIL`)

- **Status:** Accepted
- **Context:** Automated SOAR containment needs to drop malicious source IPs at the Linux host boundary on Fedora without altering baseline host firewall rules or risking self-denial of service.
- **Decision:** Execute parameterized `iptables` operations inside a dedicated `PURPLE_JAIL` chain, enforce an IP safelist (`127.0.0.1`, `::1`, `172.18.0.1`, RFC 1918 ranges), require `X-SOAR-Token` authentication, and append structured JSON audit records to `/var/log/soar_containment.json`.
- **Consequences:**
  - Isolates automated drops from general host rules and makes rollback/unblocking deterministic.
  - Requires `CAP_NET_ADMIN` and SELinux-aware volume/path handling (`:z`) when running in containers.
  - Rejects `shell=True` subprocess calls to prevent command injection.
- **Rejected Alternatives:**
  - Modifying default `INPUT` rules directly without a dedicated chain (higher operational risk and harder audit/cleanup).
  - Relying solely on application-layer rate limiting (leaves host/container network stack exposed).
