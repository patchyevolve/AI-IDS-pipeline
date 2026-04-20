# Attack Engine

Adaptive attack generation system that learns from IDS feedback and evolves evasion strategies using a genetic mutation engine.

> For testing your own IDS only. Do not use against systems you don't own.

---

## Modes

### 1. Local — synthetic events, private pipeline

Runs a full CNN → RNN → Decoder pipeline internally. Nothing goes over the network. Good for offline testing and profile development.

```bash
python attacker/run_attacker.py --synthetic
```

### 2. Real packets — actual traffic over Wi-Fi

Sends real TCP/UDP packets to a target IP using scapy. The IDS machine captures them via its live Wi-Fi capture automatically — no port configuration needed on the IDS side.

```bash
# From laptop B, targeting laptop A's IP
python attacker/run_attacker.py --real 10.138.92.86
```

Requires:
- scapy installed
- Npcap on Windows (same requirement as the IDS)
- Run as Administrator

### 3. Remote — synthetic events injected into IDS pipeline

Sends synthetic event dicts over TCP to a running `run.py` instance. Events appear in the IDS dashboard exactly like live traffic. Decoder decisions stream back for fitness scoring.

```bash
# From laptop B
python attacker/run_attacker.py --remote 10.138.92.86

# IDS machine (laptop A) must be running run.py — ports 9875 and 9878 open automatically
```

---

## All Options

```
python attacker/run_attacker.py [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--real <IP>` | — | Send real packets to this IP over Wi-Fi |
| `--remote <IP>` | — | Stream synthetic events to IDS machine at this IP |
| `--remote-port <N>` | `9875` | Port for remote injection (default matches IDS listener) |
| `--rate <float>` | `0.4` | Min seconds between attacks |
| `--duration <int>` | `0` | Run for N seconds then stop. `0` = run until Ctrl+C |
| `--profile <name>` | all | Lock to one specific profile, skip evolution |
| `--target <IP>` | auto | Force a specific destination IP for synthetic events |
| `--synthetic` | off | Use fake target IPs instead of ARP scan |
| `--no-evolve` | off | Disable genetic mutation, use fixed base profiles |
| `--evolve-every <N>` | `30` | Evolve population every N attacks |
| `--list-profiles` | — | Print all base profiles and exit |

---

## Examples

```bash
# Fast synthetic run for 60 seconds
python attacker/run_attacker.py --synthetic --duration 60 --rate 0.1

# Only DoS profiles, no evolution
python attacker/run_attacker.py --synthetic --profile DoS_SYN_Flood --no-evolve

# Real packets to a specific machine, slow rate
python attacker/run_attacker.py --real 192.168.1.50 --rate 1.0

# Remote injection into running IDS dashboard
python attacker/run_attacker.py --remote 192.168.1.10 --rate 0.2

# See all available profiles
python attacker/run_attacker.py --list-profiles
```

---

## Base Attack Profiles

| Profile | Protocol | Port | Rate (Hz) | Entropy |
|---------|----------|------|-----------|---------|
| `DoS_SYN_Flood` | TCP | 80 | 8000 | 0.05 |
| `DoS_UDP_Flood` | UDP | random | 6000 | 0.10 |
| `PortScan_TCP` | TCP | random | 400 | 0.02 |
| `BruteForce_SSH` | TCP | 22 | 250 | 0.45 |
| `BruteForce_RDP` | TCP | 3389 | 180 | 0.50 |
| `C2_Beacon` | TCP | 443 | 8 | 0.88 |
| `Exfiltration_HTTPS` | TCP | 443 | 300 | 0.95 |
| `DNS_Tunnel` | UDP | 53 | 60 | 0.93 |
| `LateralMovement_SMB` | TCP | 445 | 50 | 0.60 |
| `SlowLoris` | TCP | 80 | 2 | 0.30 |

---

## How Evolution Works

1. Each profile has a fitness score based on `evaded / sent`
2. After every `--evolve-every` attacks, the population is sorted by fitness
3. Top profiles (elites) survive unchanged
4. New variants are bred via crossover of two parents + mutation
5. Blocked profiles mutate to evade — lower rate, fragment bytes, randomize ports, slow down
6. Evaded profiles are amplified slightly
7. Population grows to 20 variants across generations

---

## End-of-Session Report

When the session ends (Ctrl+C or `--duration` expires) in local mode:

- Console summary printed — which profiles evaded, evasion rates, attack classes
- `attacker/session_report.json` saved
- Evaded profiles force-written into the IDS DB as high-confidence threat records
- IDS signatures exported to `database/ids_signatures.jsonl`

In `--remote` mode the report and DB update happen on the IDS machine.

---

## Two-Laptop Setup (same hotspot)

```
Laptop A (IDS)                          Laptop B (Attacker)
─────────────────────────────────       ──────────────────────────────
python run.py                           python attacker/run_attacker.py --real <A's IP>
  live Wi-Fi capture on                   sends real TCP/UDP packets
  scapy captures B's packets    ←←←←←←   over hotspot to A
  CNN → RNN → Decoder → DB
  dashboard shows attacks live
```

Find laptop A's IP:
```bash
# Windows
ipconfig
# Look for the Wi-Fi / hotspot adapter IP e.g. 10.138.92.86
```

Then on laptop B:
```bash
python attacker/run_attacker.py --real 10.138.92.86 --rate 0.5
```

No firewall rules or port forwarding needed — scapy captures at the adapter level.
