# 🛡️ BlueshieldAA

A modular **blue team cybersecurity toolkit** written in Python.  
Built for defense, monitoring, and analysis — designed to integrate with real-world tools.

---

## Tools

| Script | Description |
|---|---|
| `examples/hashchecker_interactive.py` | Hash files and check them against VirusTotal |
| `examples/portscanner_interactive.py` | Port scanner with service versions + geolocation |
| `examples/auditor.py` | Local security auditor with score and recommendations |

## Library Modules

| Module | Description |
|---|---|
| `blueshieldaa.network` | TCP port scanning with concurrency |
| `blueshieldaa.traffic` | PCAP/PCAPNG capture analysis |
| `blueshieldaa.crypto` | Hash generation and file integrity checks |
| `blueshieldaa.logs` | Log parsing and brute-force detection |
| `blueshieldaa.integrations` | Wrappers for nmap and aircrack-ng |

---

## Installation

```bash
git clone https://github.com/AA/BlueshieldAA.git
cd BlueshieldAA
pip install -e .
```

Optional dependencies:
```bash
pip install -e ".[all]"   # scapy + python-nmap
```

---

## Usage

### HashChecker + VirusTotal
```bash
export VT_API_KEY="your_api_key_here"
python3 examples/hashchecker_interactive.py
```

### Port Scanner
```bash
sudo python3 examples/portscanner_interactive.py
```

### Security Auditor
```bash
sudo python3 examples/auditor.py
```

---

## Requirements

- Python >= 3.10
- `nmap` installed on the system (`sudo apt install nmap`)
- Optional: `scapy`, `python-nmap`

---

## Disclaimer

This toolkit is intended for **authorized security testing and analysis only**.  
Always obtain proper permission before scanning any network or system.

---

## License

MIT License
