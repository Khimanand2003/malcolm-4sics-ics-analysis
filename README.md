# ICS Network Traffic Analysis with Malcolm — 4SICS Geek Lounge Dataset

A self-directed network security and ICS forensics project: analyzing real industrial control system (ICS/SCADA) attack traffic from the 4SICS "Geek Lounge" conference lab using CISA's **Malcolm** network analysis suite and custom Python forensic tooling.

> ⚠️ Public training dataset provided by **Netresec** & **CS3Sthlm**. The traffic consists of authorized conference participants conducting hands-on assessment against an isolated demonstration ICS lab.

---

## What this project covers
- **Environment**: Deploying Malcolm (Zeek + Suricata + Arkime + OpenSearch) & custom forensic automation.
- **Dataset**: Ingesting and analyzing three full PCAP captures (25 MB / 134 MB / 200 MB; ~3.7 Million total packets).
- **Forensic Timeline**: Tracing a complete 3-day ICS reconnaissance and protocol fuzzing attack.
- **Attribution & Verification**: Distinguishing legitimate PLC write operations from attacker probing (`192.168.2.166`).

---

## 4SICS Lab Topology & Monitored Devices

| Rack / Segment | IP Address | Device Name & Description | Open Protocols |
|---|---|---|---|
| **Rack #1** | `192.168.88.15` | DirectLogic 205 (PLC) | PLC Control |
| | `192.168.88.20` | Phoenix Contact FL IL 24 BK-PAC | HTTP (80), Modbus (502) |
| | `192.168.88.25` | Advantech ADAM-5500 | FTP (21), HTTP (80, 81) |
| | `192.168.88.49` | AXIS 206 Network Camera | FTP (21), HTTP (80), UPnP |
| | `192.168.88.75` | Hirschmann EAGLE 20 Tofino Firewall | SSH (22), HTTPS (443) |
| **Rack #2** | `192.168.88.30` | Siemens SIMATIC S7-1200 (PLC) | S7comm (102), Port 5001 |
| | `192.168.88.95` | RUGGEDCOM RS910 Serial Device Server | SSH, Telnet, HTTP, Modbus (502), DNP3 (20000) |
| **Rack #3** | `192.168.88.50` | Red Lion DSP Protocol Converter | HTTP (80), Modbus (502) |
| | `192.168.88.60` | Moxa EDS-508A Managed Switch | SSH, Telnet, HTTP, Modbus (502) |
| | `192.168.88.61` | Moxa EDS-508A Managed Switch | SSH, Telnet, HTTP, Modbus (502), Ethernet/IP |
| | `192.168.88.100` | Host Engineering MB-gateway | HTTP (80), Modbus (502) |
| **Rack #4** | `192.168.88.51` | Beckhoff CX1010 PLC (WinCE) | Telnet (23), HTTP (80), 135, 443, 1234, 5120 |
| **Attacker Net**| `192.168.2.0/24` | Conference Participant / Attacker Subnet | `192.168.2.166` (Primary Attacker IP) |

---

## 3-Day Forensic Timeline & Automated Analysis Results

Running `python3 analyze_ics_pcap.py` against the full dataset yields the following empirical findings:

| Day / File | Phase | Total Packets | Modbus Requests | Attacker Packets (`192.168.2.166`) | Key Findings |
|---|---|---|---|---|---|
| **Day 1** (`151020`) | Baseline | 246,137 | 0 | 0 | Normal baseline network operations; no scanning or attacks. |
| **Day 2** (`151021`) | Recon | 1,253,100 | 19 | 0 | Web scanning + device identification (`FUNC_0x2B` Read Device ID). **Zero writes**. |
| **Day 3** (`151022`) | Active Attack | 2,274,747 | 99,548 | **69,827** | Intensive protocol fuzzing & 10,684 Modbus write commands (`WRITE_MULTIPLE_COILS`). |

---

## Key Evidence — Day 3 Modbus Write Attack

Attacker IP `192.168.2.166` targeting Moxa EDS-508A (`192.168.88.60`) and RUGGEDCOM RS910 (`192.168.88.95`) with repeated `WRITE_MULTIPLE_COILS` against coil addresses `65533–65535` at the boundary limit:

![Day 3 Modbus write attack](modbus-write-attack.png)

---

## Automated Scripts & Reproduction

### 1. Download PCAP Datasets
Download the official 4SICS PCAP files directly from Netresec:
```bash
python3 download_dataset.py
```
This saves the 3 PCAP files (~368 MB total) into the `./pcaps` folder.

### 2. Run Forensic PCAP Analyzer
Execute the native Python packet parser to extract ICS protocol stats and attacker metrics:
```bash
python3 analyze_ics_pcap.py
```

### 3. Deploy Malcolm Suite
To analyze the PCAPs inside Malcolm's web UI (Arkime + OpenSearch):
```bash
git clone https://github.com/cisagov/Malcolm.git
cd Malcolm
./Malcolm config
./Malcolm start
```

---

## Credits & License
- Dataset: **[Netresec 4SICS Dataset](https://www.netresec.com/?page=PCAP4SICS)** & **[CS3Sthlm](https://cs3sthlm.se/)**
- Full Forensic Report: [Malcolm_4SICS_Report.pdf](Malcolm_4SICS_Report.pdf)
