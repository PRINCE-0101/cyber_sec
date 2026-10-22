# ◈ Sentinel — Firewall Lab

A local firewall simulator with an interactive dashboard, Python CLI, persistent traffic journal, and explainable first-match decisions. Built for the **Cyber Security screening: Firewall Simulator** task.

**Python 3.10+ · Standard library only · No API keys · No administrator access**

> This is an educational stateless packet-filter simulator. It evaluates user-supplied packet metadata; it does not capture, send, or block real network traffic.

## Start the dashboard

```bash
git clone https://github.com/PRINCE-0101/cyber_sec.git
cd cyber_sec
python app.py
```

Open **http://127.0.0.1:8000** in your browser. On some systems use `python3` instead of `python`. On Windows, `py app.py` also works. Stop with Ctrl+C. No pip installation is needed.

The server binds only to your own machine. If port 8000 is busy, run `python app.py --port 8080`.

### Try the demo

1. Click **Run 6 demo packets**.
2. With the starter policy, the journal shows **3 allowed and 3 blocked** packets.
3. Send TCP/443 from `203.0.113.66`: it is blocked by the first rule, even though HTTPS is generally allowed.
4. Move `allow-https` above `deny-suspicious-host`, then repeat: it is allowed. This demonstrates rule precedence.
5. Restore the deny rule to the top. Add your own rule, toggle it, and inspect the decision trace.
6. Download the full journal with **Export JSONL**. Restart the app to see saved rules and logs retained.

## Requirements covered

| Screening requirement | Implementation |
| --- | --- |
| Block specific IPs | Source/destination IP and CIDR rules, IPv4 and IPv6 |
| Block/allow ports | Destination port or inclusive range, e.g. `8000-8080` |
| Protocol filtering | TCP, UDP, ICMP, or ANY |
| Log allowed/blocked actions | Append-only JSONL with UTC timestamp, packet, matched rule and trace |
| CLI or UI configuration | Both; add/delete rules in CLI, add/delete/toggle/reorder in dashboard |
| Working script/tool | `app.py`, `cli.py`, shared `firewall.py` |
| Explanation | Below and `docs/INTERVIEW.md` |
| Example test cases | `examples/packets.json`, automated tests |

## Firewall logic

Rules are checked from top to bottom. Within one rule, **all constraints must match**: source, destination, protocol, and destination port. `ANY` is a wildcard. Disabled rules are skipped. The first matching rule decides ALLOW or BLOCK and evaluation stops. If nothing matches, the default policy decides (initially BLOCK).

CIDR describes a network: `192.168.1.0/24` includes addresses from `192.168.1.0` through `192.168.1.255`. A lone IP becomes a single-host network. Host bits in CIDR inputs are normalized. ICMP has no ports and cannot match a port-constrained rule. TCP/UDP ports must be integers from 1 to 65535 in this simulator. Mixed IPv4/IPv6 endpoints are rejected.

Protocol means the supplied transport/network protocol label, **not application content inspection**. A TCP/443 packet is not verified to contain HTTPS.

## CLI

Run commands from the repository root. The dashboard creates `data/policy.json` automatically. If you have not started it, initialize once:

```bash
python cli.py init
python cli.py rules
python cli.py simulate --source 203.0.113.66 --destination 198.51.100.10 --protocol TCP --port 443
python cli.py simulate --source 192.168.1.20 --destination 198.51.100.10 --protocol ICMP
python cli.py batch examples/packets.json
python cli.py add deny-telnet BLOCK --protocol TCP --ports 23
python cli.py add allow-lab ALLOW --source 192.168.2.0/24 --protocol TCP --ports 8000-8080
python cli.py delete deny-telnet
python cli.py default BLOCK
```

`init` refuses to overwrite an existing policy. To experiment separately:

```bash
python cli.py --policy data/experiment.json init
python cli.py --policy data/experiment.json --log data/experiment.jsonl batch examples/packets.json
```

New rules append to the end. Earlier matching rules take precedence. Global `--policy` and `--log` flags go **before** the subcommand. CLI errors exit with code 2; ALLOW and BLOCK are successful simulation outcomes, both exit 0. A batch processes sequentially; an invalid later entry stops the batch but prior decisions remain logged.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests cover the six demo outcomes, precedence, disabled rules, CIDR/destination matching, IPv6, inclusive range boundaries, invalid packets/rules, ICMP, defaults, persistence, and HTTP behavior including cross-origin rejection. GitHub Actions runs tests on Python 3.10 and 3.12.

| Example | Expected with starter policy |
| --- | --- |
| Suspicious host → TCP/443 | BLOCK: deny-suspicious-host |
| Normal host → TCP/443 | ALLOW: allow-https |
| Normal host → UDP/53 | ALLOW: allow-dns |
| Local subnet → TCP/22 | ALLOW: allow-local-ssh |
| External host → TCP/22 | BLOCK: DEFAULT |
| ICMP | BLOCK: deny-ping |

## Structure

- `firewall.py`: validation, normalization, evaluation, atomic policy saving and audit logging.
- `app.py`: local HTTP API and dashboard hosting.
- `dashboard.html`: responsive interface, rule management, traffic table and trace.
- `cli.py`: argparse commands using the same engine.
- `examples/`: starter policy and six sample packets.
- `tests/`: engine and API regression tests.
- `docs/INTERVIEW.md`: architecture, design decisions and viva preparation.

Runtime files live in `data/` and are ignored by Git. The dashboard displays the latest 200 records; export contains the full journal. Policy writes use atomic file replacement. Run only one writer (dashboard or CLI) against a data directory at a time: concurrent policy editing is not coordinated. The local server is for a single-user demo, not public hosting. Logs grow without automatic rotation. Evaluation is O(R) per packet for R rules. No stateful connection tracking, NAT, deep packet inspection, or live packet capture is implemented.
