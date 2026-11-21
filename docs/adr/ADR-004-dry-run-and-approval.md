# ADR-004: Dry-Run Simulation Mode, Safelist Guardrails, and High-Impact Approval

- **Status:** Accepted
- **Context:** Automated host firewall containment (`iptables` / `PURPLE_JAIL`) can cause accidental self-DoS or service disruption if triggered by false positives, misconfigured detection rules, or spoofed headers.
- **Decision:**
  - Support a `dry_run` execution mode that evaluates alerts, checks token authentication, severity, and IPv4/IPv6 safelists, and records structured audit/simulation outcomes without mutating live kernel firewall rules.
  - Enforce network safelists (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`) before any containment action.
  - Reserve broad or high-impact containment actions for explicit approval policies or higher-confidence correlation rules.
- **Consequences:**
  - Teams can validate end-to-end alert ingestion, MITRE rule correlation, and SOAR decision logic safely before enabling active packet dropping.
  - Audit trails distinguish simulated (`dry_run`) decisions from enforced (`blocked`) actions.
- **Rejected Alternatives:**
  - Unconditional permanent `iptables DROP` rules on every single alert without simulation, safelist enforcement, or rollback path.
