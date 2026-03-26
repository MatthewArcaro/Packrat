from collections import Counter

def analyze(parsed_packets):
    total_packets = len(parsed_packets)
    total_bytes = sum(pkt["size"] for pkt in parsed_packets)

    ## count protocols
    protocol_counts = Counter(pkt["protocol"] for pkt in parsed_packets)

    ## count IPs (excluding ARP)
    ip_packets = [pkt for pkt in parsed_packets if pkt["protocol"] != "ARP" and pkt["src"]]
    src_count = Counter(pkt["src"] for pkt in ip_packets)
    dst_count = Counter(pkt["dst"] for pkt in ip_packets)

    ## build IP summary
    all_ips = set(list(src_count.keys()) + list(dst_count.keys()))
    ip_sum = []
    for ip in all_ips:
        ip_sum.append({
            "ip": ip,
            "sent": src_count.get(ip, 0),
            "received": dst_count.get(ip, 0),
        })

    ## most active IP first
    ip_sum.sort(key=lambda x: x["sent"] + x["received"], reverse=True) ## shoutout to professor Liang

    ## ARP summary
    arp_packets = [pkt for pkt in parsed_packets if pkt["protocol"] == "ARP"]
    arp_requests = [pkt for pkt in arp_packets if pkt["info"].get("arp_op") == "request"]
    arp_replies = [pkt for pkt in arp_packets if pkt["info"].get("arp_op") == "reply"]

    ## DNS summary
    dns_packets = [pkt for pkt in parsed_packets if pkt["protocol"] == "DNS"]
    dns_queries = [
        pkt["info"]["dns_query"]
        for pkt in dns_packets
        if "dns_query" in pkt["info"]
    ]
    top_dns = Counter(dns_queries).most_common(10)

    ## HTTP summary
    http_packets = [pkt for pkt in parsed_packets if pkt["protocol"] == "HTTP"]
    http_requests = [pkt for pkt in http_packets if "http_host" in pkt["info"]]
    top_hosts = Counter(pkt["info"]["http_host"] for pkt in http_requests).most_common(10)

    ## HTTPS summary
    https_packets = [pkt for pkt in parsed_packets if pkt["protocol"] == "HTTPS"]
    tls_handshakes = [pkt for pkt in https_packets if pkt["info"].get("tls") == "handshake"]

    ## SSH summary
    ssh_packets = [pkt for pkt in parsed_packets if pkt["protocol"] == "SSH"]

    ## FTP summary
    ftp_packets = [pkt for pkt in parsed_packets if pkt["protocol"] == "FTP"]

    ## SMTP summary
    smtp_packets = [pkt for pkt in parsed_packets if pkt["protocol"] == "SMTP"]

    ## IMAP summary
    imap_packets = [pkt for pkt in parsed_packets if pkt["protocol"] == "IMAP"]

    ## anomalies
    anomalies = []

    # high traffic IPs
    for ip, count in src_count.items():
        if count > 5000:
            anomalies.append(f"High traffic from {ip} — {count} packets sent")

    # suspicious ports
    sus_ports = [4444, 1337, 31337, 6666, 6667]
    for packet in parsed_packets:
        if packet["dport"] in sus_ports or packet["sport"] in sus_ports:
            port = packet["dport"] if packet["dport"] in sus_ports else packet["sport"]
            anomalies.append(f"Sus port {port} detected during this conversation: {packet['src']} -> {packet['dst']}")
            break

    # excessive ARP requests (possible ARP scan)
    if len(arp_requests) > 50:
        anomalies.append(f"Excessive ARP requests detected — {len(arp_requests)} requests, possible ARP scan")

    # excessive DNS queries (possible DNS tunneling)
    if len(dns_queries) > 500:
        anomalies.append(f"High DNS query volume — {len(dns_queries)} queries, possible DNS tunneling")

    # FTP detected - always worth flagging
    if len(ftp_packets) > 0:
        anomalies.append(f"FTP traffic detected — {len(ftp_packets)} packets, FTP sends credentials in plaintext!")

    # SMTP detected
    if len(smtp_packets) > 0:
        anomalies.append(f"SMTP traffic detected — {len(smtp_packets)} packets")

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_counts": dict(protocol_counts),
        "ip_summary": ip_sum[:10],
        "arp": {
            "total": len(arp_packets),
            "requests": len(arp_requests),
            "replies": len(arp_replies),
        },
        "dns": {
            "total": len(dns_packets),
            "unique_queries": len(set(dns_queries)),
            "top_queries": top_dns,
        },
        "http": {
            "total": len(http_packets),
            "top_hosts": top_hosts,
        },
        "https": {
            "total": len(https_packets),
            "tls_handshakes": len(tls_handshakes),
        },
        "ssh": {
            "total": len(ssh_packets),
        },
        "ftp": {
            "total": len(ftp_packets),
        },
        "smtp": {
            "total": len(smtp_packets),
        },
        "imap": {
            "total": len(imap_packets),
        },
        "anomalies": list(set(anomalies))
    }