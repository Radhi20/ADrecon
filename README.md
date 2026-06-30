# ADrecon — Active Directory Attack Chain Automation

> An interactive Python tool that automates Active Directory enumeration and attack simulation, producing detailed HTML/JSON reports.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Protocol](https://img.shields.io/badge/Protocol-LDAP%20%2F%20Kerberos-green)
![Target](https://img.shields.io/badge/Target-Active%20Directory-red)

---

## Overview

ADrecon automates the reconnaissance and attack simulation phases of an Active Directory pentest. It connects via LDAP, enumerates domain objects, identifies misconfigurations, and simulates offensive techniques like Kerberoasting and AS-REP Roasting.

### Attack Surface Covered

| Phase | Description |
|---|---|
| LDAP Enumeration | Users, groups, computers, OUs |
| UAC Flag Analysis | Disabled accounts, no-expiry passwords, no-preauth |
| Kerberoasting Detection | Accounts with SPNs set |
| AS-REP Roasting Detection | Accounts with pre-auth disabled |
| Password Policy Audit | Min length, history, lockout threshold |
| Admin Share Check | SMB access simulation |
| Report Generation | JSON + styled HTML report |

---

## Lab Architecture

```
┌─────────────────────────────────────────┐
│            VMware Lab (Host-Only)        │
│                                          │
│  Kali Linux      192.168.100.30          │
│  (ADrecon)  ──→  DC01  192.168.100.10   │
│                  WIN10 192.168.100.20    │
│                  Domain: corp.local      │
└─────────────────────────────────────────┘
```

---

## Setup

```bash
pip3 install -r requirements.txt --break-system-packages
```

## Usage

### Interactive mode (menu)
```bash
python3 adrecon.py
```

### CLI mode (full auto scan)
```bash
python3 adrecon.py --dc-ip 192.168.100.10 --domain corp.local --user jsmith --password Password123! --auto
```

### Options
```
--dc-ip      Domain Controller IP
--domain     Domain name (default: corp.local)
--user       Username
--password   Password
--auto       Run full scan without interactive menu
```

---

## Output

Each scan generates two files in `reports/`:
- `adrecon_<timestamp>.json` — raw data
- `adrecon_<timestamp>.html` — styled report with findings

---

