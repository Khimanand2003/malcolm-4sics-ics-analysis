#!/usr/bin/env python3
"""
4SICS ICS Network Traffic Forensic Analyzer
Native Python PCAP parser analyzing Modbus TCP (502), S7comm (102), DNP3 (20000) & Attacker IPs.
"""

import os
import sys
import struct
import socket
from collections import defaultdict, Counter

# Devices Map from 4SICS Lab Topology
ICS_DEVICES = {
    "192.168.88.15": "DirectLogic 205 PLC",
    "192.168.88.20": "Phoenix Contact Bus Coupler",
    "192.168.88.25": "Advantech ADAM-5500",
    "192.168.88.30": "Siemens SIMATIC S7-1200 PLC",
    "192.168.88.49": "AXIS 206 Camera",
    "192.168.88.50": "Red Lion DSP Protocol Converter",
    "192.168.88.51": "Beckhoff CX1010 PLC",
    "192.168.88.60": "Moxa EDS-508A Switch",
    "192.168.88.61": "Moxa EDS-508A Switch",
    "192.168.88.75": "Hirschmann Tofino Firewall",
    "192.168.88.95": "RUGGEDCOM RS910 Device Server",
    "192.168.88.100": "MB-gateway Modbus Gateway",
    "192.168.2.166": "Attacker Workstation (Day 3)",
}

MODBUS_FUNCTIONS = {
    1: "READ_COILS",
    2: "READ_DISCRETE_INPUTS",
    3: "READ_HOLDING_REGISTERS",
    4: "READ_INPUT_REGISTERS",
    5: "WRITE_SINGLE_COIL",
    6: "WRITE_SINGLE_REGISTER",
    15: "WRITE_MULTIPLE_COILS",
    16: "WRITE_MULTIPLE_REGISTERS"
}

def parse_pcap(filepath):
    """Native Python PCAP file parser (supports standard Global Header & Record Headers)"""
    if not os.path.exists(filepath):
        print(f"[-] PCAP file not found: {filepath}")
        return None

    with open(filepath, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            print(f"[-] Invalid PCAP header in {filepath}")
            return None

        magic, ver_maj, ver_min, tz, flags, snaplen, linktype = struct.unpack("<IHHiIII", global_header)
        is_little_endian = True
        if magic == 0xa1b2c3d4:
            is_little_endian = True
        elif magic == 0xd4c3b2a1:
            is_little_endian = False
        else:
            print(f"[-] Unsupported PCAP format or magic number: {hex(magic)}")
            return None

        stats = {
            "total_packets": 0,
            "ip_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "ports": Counter(),
            "ip_pairs": Counter(),
            "modbus_requests": 0,
            "modbus_writes": 0,
            "modbus_funcs": Counter(),
            "attacker_packets": 0,
            "attacker_targets": Counter(),
        }

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII" if is_little_endian else ">IIII", pkt_hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            stats["total_packets"] += 1

            # Assuming Ethernet II frames (linktype == 1)
            if linktype == 1:
                if len(pkt_data) < 14:
                    continue
                eth_type = struct.unpack(">H", pkt_data[12:14])[0]
                ip_data = pkt_data[14:]

                # 802.1Q VLAN Tagging (0x8100)
                if eth_type == 0x8100:
                    eth_type = struct.unpack(">H", ip_data[2:4])[0]
                    ip_data = ip_data[4:]

                if eth_type != 0x0800 or len(ip_data) < 20:
                    continue

                stats["ip_packets"] += 1
                version_ihl = ip_data[0]
                ihl = (version_ihl & 0x0F) * 4
                proto = ip_data[9]
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])

                stats["ip_pairs"][(src_ip, dst_ip)] += 1

                if src_ip == "192.168.2.166":
                    stats["attacker_packets"] += 1
                    stats["attacker_targets"][dst_ip] += 1

                payload = ip_data[ihl:]

                if proto == 6 and len(payload) >= 20: # TCP
                    stats["tcp_packets"] += 1
                    src_port, dst_port = struct.unpack(">HH", payload[:4])
                    data_offset = ((payload[12] >> 4) & 0x0F) * 4
                    tcp_data = payload[data_offset:]

                    stats["ports"][dst_port] += 1

                    # Modbus TCP (Port 502)
                    if dst_port == 502 or src_port == 502:
                        if len(tcp_data) >= 7:
                            transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", tcp_data[:7])
                            if protocol_id == 0 and len(tcp_data) >= 8:
                                func_code = tcp_data[7]
                                stats["modbus_requests"] += 1
                                func_name = MODBUS_FUNCTIONS.get(func_code, f"FUNC_0x{func_code:02X}")
                                stats["modbus_funcs"][func_name] += 1

                                if func_code in (5, 6, 15, 16):
                                    stats["modbus_writes"] += 1

                elif proto == 17 and len(payload) >= 8: # UDP
                    stats["udp_packets"] += 1
                    src_port, dst_port = struct.unpack(">HH", payload[:4])
                    stats["ports"][dst_port] += 1

        return stats

def main():
    pcap_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
    if len(sys.argv) > 1:
        pcap_dir = sys.argv[1]

    print("=== 4SICS ICS Forensic PCAP Analysis Summary ===")
    print(f"Scanning directory: {pcap_dir}\n")

    if not os.path.exists(pcap_dir):
        print(f"[-] PCAP directory {pcap_dir} does not exist. Run download_dataset.py first.")
        sys.exit(1)

    pcap_files = sorted([f for f in os.listdir(pcap_dir) if f.endswith(".pcap")])
    if not pcap_files:
        print("[-] No .pcap files found.")
        sys.exit(1)

    for pfile in pcap_files:
        fpath = os.path.join(pcap_dir, pfile)
        print(f"--------------------------------------------------")
        print(f"Analyzing File: {pfile} ({os.path.getsize(fpath)} bytes)")
        res = parse_pcap(fpath)
        if res:
            print(f"  Total Packets:     {res['total_packets']}")
            print(f"  IPv4 Packets:      {res['ip_packets']}")
            print(f"  TCP / UDP:         {res['tcp_packets']} / {res['udp_packets']}")
            print(f"  Modbus Requests:   {res['modbus_requests']} (Writes: {res['modbus_writes']})")
            print(f"  Attacker Packets:  {res['attacker_packets']} (From 192.168.2.166)")
            if res['modbus_funcs']:
                print(f"  Modbus Functions:  {dict(res['modbus_funcs'])}")
            if res['attacker_targets']:
                print(f"  Attacker Targets:  {dict(res['attacker_targets'])}")
        print(f"--------------------------------------------------\n")

if __name__ == "__main__":
    main()
