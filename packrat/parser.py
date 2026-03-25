from scapy.all import rdpcap, IP, TCP, UDP, ICMP

def parse_pcap(filepath):
    print(f"[*] Loading {filepath}...")
    
    try:
        packets = rdpcap(filepath) ## reads pcap fiel
    except FileNotFoundError:
        print(f"Your file couldn't be found :(")
        return None
    except Exception as e:
        print(f"Error reading file: {e}. Is it a pcap file?")
        return None

    parsed = []

    for pkt in packets:
        entry = {
            "size": len(pkt),
            "protocol": None,
            "src": None,
            "dst": None,
            "sport": None,
            "dport": None,
        }

        if IP in pkt:
            entry["src"] = pkt[IP].src
            entry["dst"] = pkt[IP].dst

            if TCP in pkt: ## if TCP we enter TCP dta
                entry["protocol"] = "TCP"
                entry["sport"] = pkt[TCP].sport
                entry["dport"] = pkt[TCP].dport

            elif UDP in pkt: ## if UDP we enter that
                entry["protocol"] = "UDP"
                entry["sport"] = pkt[UDP].sport
                entry["dport"] = pkt[UDP].dport

            elif ICMP in pkt: ## PINGGGG
                entry["protocol"] = "ICMP"
            else: ## to bored we can do that later
                entry["protocol"] = "OTHER"

            parsed.append(entry) ## add it the list

    print(f"Parsed {len(parsed)} IP packets successfully. :) ")
    return parsed