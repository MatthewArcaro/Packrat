from collections import Counter, defaultdict

def detect(parsed_packets):
    findings = []

    src_syn = Counter()
    src_icmp = Counter()
    src_udp = Counter()
    src_ports = defaultdict(set)
    arp_requests = 0

    for pkt in parsed_packets:
        proto = pkt["protocol"]
        src = pkt["src"]

        # SYN flood — count TCP SYN packets per source
        if proto == "TCP" and pkt["info"].get("tcp_flags") == "S":
            src_syn[src] += 1

        # ICMP flood
        if proto == "ICMP":
            src_icmp[src] += 1

        # UDP flood
        if proto == "UDP":
            src_udp[src] += 1

        # Port scan — track unique destination ports per source
        if proto in ("TCP", "UDP") and pkt["dport"] is not None:
            src_ports[src].add(pkt["dport"])

        # ARP scan
        if proto == "ARP" and pkt["info"].get("arp_op") == "request":
            arp_requests += 1

    # SYN flood threshold
    for ip, count in src_syn.items():
        if count > 1000:
            findings.append({
                "type": "SYN Flood",
                "severity": "high",
                "src": ip,
                "detail": f"{count} SYN packets from {ip}"
            })

    # ICMP flood threshold
    for ip, count in src_icmp.items():
        if count > 500:
            findings.append({
                "type": "ICMP Flood",
                "severity": "high",
                "src": ip,
                "detail": f"{count} ICMP packets from {ip}"
            })

    # UDP flood threshold
    for ip, count in src_udp.items():
        if count > 1000:
            findings.append({
                "type": "UDP Flood",
                "severity": "high",
                "src": ip,
                "detail": f"{count} UDP packets from {ip}"
            })

    # Port scan threshold
    for ip, ports in src_ports.items():
        if len(ports) > 50:
            findings.append({
                "type": "Port Scan",
                "severity": "medium",
                "src": ip,
                "detail": f"{ip} contacted {len(ports)} unique ports"
            })

    # ARP scan threshold
    if arp_requests > 50:
        findings.append({
            "type": "ARP Scan",
            "severity": "medium",
            "src": "unknown",
            "detail": f"{arp_requests} ARP requests detected, possible ARP scan"
        })

    return findings