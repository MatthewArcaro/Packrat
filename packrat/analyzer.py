from collections import Counter

def analyze(parsed_packets):
    total_packets = len(parsed_packets) 
    total_bytes = sum(pkt["size"] for pkt in parsed_packets)

    ### count the amount of packets
    protocol_counts = Counter(pkt["protocol"] for pkt in parsed_packets)

    #Count IPs
    src_count = Counter(pkt["src"] for pkt in parsed_packets)
    dst_count = Counter(pkt["dst"] for pkt in parsed_packets)

    ## build the full summary 
    all_ips = set(list(src_count.keys()) + list(dst_count.keys())) ## adds both the keys together
    ip_sum = []

    ## for every single IP we are getting the src sent and receied
    for ip in all_ips:
        ip_sum.append({
            "ip": ip,
            "sent": src_count.get(ip, 0),
            "received": dst_count.get(ip,0),
        })
    

    ## make the most active IP go first
    ip_sum.sort(key=lambda x: x["sent"] + x["received"], reverse=True) ## shoutout to professor Liang

    anomalies = []

    for ip, count in src_count.items():
        if count > 1000:
            anomalies.append(f"Alot of traffic from {ip} was sent out. Exactly {count} packets!")
    

    sus_ports = [4444, 1337, 31337, 6666, 6667]
    for packet in parsed_packets:
        if packet["dport"] in sus_ports or packet["sport"] in sus_ports:
            port = packet["dport"] if packet["dport"] in sus_ports else packet["sport"]
            anomalies.append(f"Sus port {port} detected during this conversation: {packet['src']} -> {packet['dst']}")
            break

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_counts": dict(protocol_counts),
        "ip_summary": ip_sum[:10],  # top 10 IPs
        "anomalies": list(set(anomalies))  # deduplicate
    }

