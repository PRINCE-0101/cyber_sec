# Presenting Sentinel

## 30-second introduction

“Sentinel is a firewall simulator I can use to demonstrate packet filtering. I configure rules based on IP addresses, destination ports and protocols. A shared Python engine checks rules in order, returns the first matching decision and saves an audit log. I built both a browser dashboard and a command-line interface, so the same logic is usable visually or through scripts.”

Study the code and adapt this explanation to what you can personally explain. Follow your club's requirements for disclosing assistance.

## Architecture

Browser → local Python HTTP API → validation → first-match rule engine → decision + JSONL log → dashboard.
CLI → the same validation and rule engine → terminal output + JSONL log.
Rules are stored in JSON, independent of either interface.

## Common questions

**What is a firewall?** A system that permits or blocks traffic according to policy. This project demonstrates the decision logic using synthetic packet metadata.

**Why Python?** `ipaddress`, `argparse`, `http.server`, `json`, and `unittest` cover the task without external packages, making setup reproducible.

**Why first match?** It makes precedence explicit and gives deterministic decisions. A specific deny rule should usually precede a broad allow rule. A general allow placed first can shadow later restrictions.

**What is default deny?** Traffic is blocked unless a matching rule allows it. This is the initial default; the user can change it.

**What is CIDR?** A compact network prefix notation. `/24` fixes the first 24 bits of an IPv4 address. `/32` is one IPv4 host; `/128` is one IPv6 host.

**TCP versus UDP versus ICMP?** TCP offers connection-oriented delivery, UDP sends datagrams, and ICMP carries control/error information. ICMP does not use TCP/UDP ports.

**What gets logged?** Time in UTC, normalized packet fields, final action, matching rule ID, and the trace of evaluated rules. Both allowed and blocked valid packets are recorded. Invalid input is rejected before simulation.

**What does stateless mean?** Each packet is judged independently. The engine does not remember handshakes or established connections.

**Does this protect my computer?** No. It is a simulator, not an OS firewall. Real enforcement requires integration with system networking facilities.

**Why a shared engine?** It prevents the CLI and dashboard from disagreeing and makes the policy logic independently testable.

**What were the tricky cases?** Overlapping rules, invalid IPs, port-range boundaries, ICMP without ports, disabled rules, IPv6, and default decisions.

**What would you improve?** Policy snapshots attached to logs, shadowed-rule detection, log rotation, concurrent editing protection, stateful flow simulation, and more extensive browser automation tests.

## Three-minute live demo

1. Start `python app.py` and open the printed URL.
2. Run the demo. Explain the three ALLOW and three BLOCK outcomes.
3. Send the suspicious host to TCP/443 and show its matching deny rule.
4. Move the HTTPS allow above the deny; resend and explain the changed verdict.
5. Restore the deny rule, export logs, and run the unit tests.

Avoid saying the simulator detects malware, blocks real attacks, or validates HTTPS content. Those are outside its implementation.
