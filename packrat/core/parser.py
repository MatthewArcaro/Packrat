from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

def parse_pcap(filepath, skip_dns=False):
    try:
        packets = rdpcap(filepath)
    except FileNotFoundError:
        return None, "Your file couldn't be found :("
    except Exception as e:
        return None, f"[!] Error reading file: {e}. Is it a pcap file?"

    parsed = []

    for pkt in packets:
        entry = {
            "size": len(pkt),
            "protocol": "OTHER",
            "src": None,
            "dst": None,
            "sport": None,
            "dport": None,
            "info": {}
        }

        if ARP in pkt:
            entry["protocol"] = "ARP"
            entry["src"] = pkt[ARP].psrc
            entry["dst"] = pkt[ARP].pdst
            entry["info"]["arp_op"] = "request" if pkt[ARP].op == 1 else "reply"
            parsed.append(entry)
            continue

        if IP in pkt:
            entry["src"] = pkt[IP].src
            entry["dst"] = pkt[IP].dst
        elif IPv6 in pkt:
            entry["src"] = pkt[IPv6].src
            entry["dst"] = pkt[IPv6].dst
            entry["protocol"] = "IPv6"

        if IP in pkt or IPv6 in pkt:
            if TCP in pkt:
                entry["protocol"] = "TCP"
                entry["sport"] = pkt[TCP].sport
                entry["dport"] = pkt[TCP].dport
                entry["info"]["tcp_flags"] = str(pkt[TCP].flags)

                if (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and Raw in pkt:
                    entry["protocol"] = "HTTP"
                    if HTTPRequest in pkt:
                        entry["info"]["http_method"] = pkt[HTTPRequest].Method.decode(errors="ignore")
                        entry["info"]["http_host"] = pkt[HTTPRequest].Host.decode(errors="ignore")
                        entry["info"]["http_path"] = pkt[HTTPRequest].Path.decode(errors="ignore")
                    elif HTTPResponse in pkt:
                        entry["info"]["http_status"] = pkt[HTTPResponse].Status_Code.decode(errors="ignore")

                elif (pkt[TCP].dport == 443 or pkt[TCP].sport == 443) and Raw in pkt:
                    entry["protocol"] = "HTTPS"
                    payload = pkt[Raw].load
                    if payload[0:1] == b'\x16':
                        entry["info"]["tls"] = "handshake"
                    else:
                        entry["info"]["tls"] = "encrypted data"

                elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                    entry["protocol"] = "SSH"

                elif pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                    entry["protocol"] = "FTP"

                elif pkt[TCP].dport == 25 or pkt[TCP].sport == 25:
                    entry["protocol"] = "SMTP"

                elif pkt[TCP].dport == 143 or pkt[TCP].sport == 143:
                    entry["protocol"] = "IMAP"

            elif UDP in pkt:
                entry["protocol"] = "UDP"
                entry["sport"] = pkt[UDP].sport
                entry["dport"] = pkt[UDP].dport

                if DNS in pkt:
                    entry["protocol"] = "DNS"
                    if pkt[DNS].qr == 0 and pkt[DNS].qdcount > 0:
                        entry["info"]["dns_query"] = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                    elif pkt[DNS].qr == 1:
                        entry["info"]["dns_response"] = True
                elif pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    entry["protocol"] = "DNS"

            elif ICMP in pkt:
                entry["protocol"] = "ICMP"

            parsed.append(entry)

    return parsed, None