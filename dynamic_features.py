"""
Layer 2 — Dynamic Analysis Feature Extractor
Extracts exactly 39 network features from a .pcap file.
Feature extraction logic from dynamic_anlaysis_v2.ipynb (cells 8 and 17)
"""

import math
import numpy as np
from collections import Counter
from typing import Optional

# scapy imports — all at top level, correct for all versions
from scapy.all import rdpcap
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

FEATURE_COLUMNS = [
    "num_packets", "total_size", "mean_packet_size", "std_packet_size",
    "mean_inter_arrival", "std_inter_arrival", "tcp_count", "udp_count",
    "tcp_ratio", "udp_ratio", "SYN", "ACK", "FIN", "PSH", "URG", "RST",
    "unique_src_ips", "unique_dst_ips", "protocols", "dns_query_count",
    "unique_domain_count", "query_types", "most_common_tcp_port",
    "most_common_udp_port", "unique_tcp_ports", "unique_udp_ports",
    "mean_entropy", "total_payload_size", "mean_payload_size",
    "std_payload_size", "min_payload_size", "max_payload_size",
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"
]


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequency = Counter(data)
    probabilities = [freq / len(data) for freq in frequency.values()]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def _extract_entropy(packets) -> float:
    entropies = [
        _calculate_entropy(bytes(pkt[Raw].load))
        for pkt in packets
        if pkt.haslayer(Raw) and pkt[Raw].load
    ]
    return float(sum(entropies) / len(entropies)) if entropies else 0.0


def _extract_payload_sizes(packets):
    sizes = [len(pkt[Raw].load) for pkt in packets if pkt.haslayer(Raw)]
    if not sizes:
        return 0, 0.0, 0.0, 0, 0
    return (
        sum(sizes),
        float(np.mean(sizes)),
        float(np.std(sizes)),
        min(sizes),
        max(sizes)
    )


def _extract_port_patterns(packets):
    tcp_ports, udp_ports = {}, {}
    for pkt in packets:
        if pkt.haslayer(TCP):
            p = min(pkt[TCP].sport, pkt[TCP].dport)
            tcp_ports[p] = tcp_ports.get(p, 0) + 1
        if pkt.haslayer(UDP):
            p = min(pkt[UDP].sport, pkt[UDP].dport)
            udp_ports[p] = udp_ports.get(p, 0) + 1
    return tcp_ports, udp_ports


def _extract_dns_features(packets):
    dns_queries = [p for p in packets if p.haslayer(DNS) and p.haslayer(DNSQR)]
    unique_domains = set()
    query_types = set()
    for pkt in dns_queries:
        try:
            domain = pkt[DNSQR].qname.decode('utf-8').strip('.')
            unique_domains.add(domain)
            query_types.add(pkt[DNSQR].qtype)
        except Exception:
            pass
    qt_str = ','.join(map(str, query_types)) if query_types else 'None'
    return len(dns_queries), len(unique_domains), qt_str


def _extract_http_methods(packets) -> dict:
    methods = {m: 0 for m in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']}
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8')
                first_word = payload.split('\n')[0].split()
                if first_word and first_word[0] in methods:
                    methods[first_word[0]] += 1
            except (UnicodeDecodeError, IndexError):
                pass
    return methods


def extract_features_from_pcap(pcap_path: str) -> Optional[dict]:
    """
    Extract 39 network features from a .pcap file.
    Returns dict with keys matching FEATURE_COLUMNS, or None on failure.
    """
    try:
        packets = rdpcap(pcap_path)
        if not packets:
            print(f"[Layer2] Empty pcap: {pcap_path}")
            return None
    except Exception as e:
        print(f"[Layer2] Failed to read pcap {pcap_path}: {e}")
        return None

    try:
        num_packets = len(packets)
        total_size  = sum(len(p) for p in packets)
        pkt_sizes   = [len(p) for p in packets if len(p) > 0]
        mean_packet_size = float(np.mean(pkt_sizes)) if pkt_sizes else 0.0
        std_packet_size  = float(np.std(pkt_sizes))  if pkt_sizes else 0.0

        iats = [float(packets[i+1].time - packets[i].time)
                for i in range(len(packets) - 1)]
        mean_inter_arrival = float(np.mean(iats)) if iats else 0.0
        std_inter_arrival  = float(np.std(iats))  if iats else 0.0

        tcp_pkts  = [p for p in packets if p.haslayer(TCP)]
        tcp_count = len(tcp_pkts)
        udp_count = sum(1 for p in packets if p.haslayer(UDP))
        tcp_ratio = float(tcp_count) / num_packets if num_packets else 0.0
        udp_ratio = float(udp_count) / num_packets if num_packets else 0.0

        flags_raw = {'SYN': 0, 'ACK': 0, 'FIN': 0, 'PSH': 0, 'URG': 0, 'RST': 0}
        for pkt in tcp_pkts:
            f = pkt[TCP].flags
            if f & 0x02: flags_raw['SYN'] += 1
            if f & 0x10: flags_raw['ACK'] += 1
            if f & 0x01: flags_raw['FIN'] += 1
            if f & 0x08: flags_raw['PSH'] += 1
            if f & 0x20: flags_raw['URG'] += 1
            if f & 0x04: flags_raw['RST'] += 1
        flags = {k: v / tcp_count if tcp_count else 0 for k, v in flags_raw.items()}

        src_ips, dst_ips, protos = set(), set(), set()
        for pkt in packets:
            if pkt.haslayer(IP):
                src_ips.add(pkt[IP].src)
                dst_ips.add(pkt[IP].dst)
                if hasattr(pkt[IP], 'proto'):
                    protos.add(pkt[IP].proto)

        protocols_str = ','.join(map(str, protos)) if protos else 'None'

        dns_query_count, unique_domain_count, query_types_str = \
            _extract_dns_features(packets)

        http_methods = _extract_http_methods(packets)

        tcp_ports, udp_ports = _extract_port_patterns(packets)
        most_common_tcp_port = max(tcp_ports, key=tcp_ports.get) if tcp_ports else None
        most_common_udp_port = max(udp_ports, key=udp_ports.get) if udp_ports else None

        mean_entropy = _extract_entropy(packets)
        total_payload, mean_payload, std_payload, min_payload, max_payload = \
            _extract_payload_sizes(packets)

        return {
            "num_packets":          num_packets,
            "total_size":           total_size,
            "mean_packet_size":     mean_packet_size,
            "std_packet_size":      std_packet_size,
            "mean_inter_arrival":   mean_inter_arrival,
            "std_inter_arrival":    std_inter_arrival,
            "tcp_count":            tcp_count,
            "udp_count":            udp_count,
            "tcp_ratio":            tcp_ratio,
            "udp_ratio":            udp_ratio,
            "SYN":                  flags['SYN'],
            "ACK":                  flags['ACK'],
            "FIN":                  flags['FIN'],
            "PSH":                  flags['PSH'],
            "URG":                  flags['URG'],
            "RST":                  flags['RST'],
            "unique_src_ips":       len(src_ips),
            "unique_dst_ips":       len(dst_ips),
            "protocols":            protocols_str,
            "dns_query_count":      dns_query_count,
            "unique_domain_count":  unique_domain_count,
            "query_types":          query_types_str,
            "most_common_tcp_port": most_common_tcp_port,
            "most_common_udp_port": most_common_udp_port,
            "unique_tcp_ports":     len(tcp_ports),
            "unique_udp_ports":     len(udp_ports),
            "mean_entropy":         mean_entropy,
            "total_payload_size":   total_payload,
            "mean_payload_size":    mean_payload,
            "std_payload_size":     std_payload,
            "min_payload_size":     min_payload,
            "max_payload_size":     max_payload,
            **http_methods,
        }

    except Exception as e:
        print(f"[Layer2] Feature extraction error: {e}")
        return None


def features_to_vector(features: dict) -> list:
    """Convert features dict to ordered list matching FEATURE_COLUMNS."""
    row = []
    for col in FEATURE_COLUMNS:
        val = features.get(col, 0)
        if val is None:
            val = 0
        if isinstance(val, str):
            val = 0 if val in ('None', '') else len(val.split(','))
        row.append(float(val))
    return row
