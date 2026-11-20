# Runbook: False Positive Triage and Manual `PURPLE_JAIL` Unblock (NIST SP 800-61 Rev. 2)

## 1. Trigger Conditions
- A legitimate internal scanner, proxy, or user IP was inserted into the `PURPLE_JAIL` Netfilter chain.
- An alert fired on benign application traffic (for example, `/rest/products/search?q=apple`).

## 2. Triage and Containment Verification
1. Inspect active rules in `PURPLE_JAIL` with line numbers:
   `sudo iptables -L PURPLE_JAIL -v -n --line-numbers`
2. Inspect recent ECS containment records:
   `tail -n 50 /var/log/soar_containment.json`
3. Verify whether the source IP belongs to a protected range or requires an explicit safelist CIDR entry.

## 3. Manual Unblock Procedure
1. Remove the offending rule by line number (replace `<LINE>` with the target index):
   `sudo iptables -D PURPLE_JAIL <LINE>`
2. Confirm the source IP is no longer listed in `PURPLE_JAIL`:
   `sudo iptables -L PURPLE_JAIL -v -n --line-numbers`
3. Record the incident disposition and post-containment verification in the incident log.
