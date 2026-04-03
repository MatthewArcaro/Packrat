import argparse
from packrat.parser import parse_pcap
from packrat.analyzer import analyze
from packrat.renderer import render
from packrat.exporter import export

def main():
    parser = argparse.ArgumentParser(
        prog="packrat",
        description="🐀 packrat — a clean, human-readable packet analyzer"
    )
    parser.add_argument("filepath", help="path to your .pcap file")
    parser.add_argument("--export", choices=["json", "html", "txt"], help="export results to a file")
    parser.add_argument("--filter", help="filter by IP address or protocol (e.g. 10.2.28.88 or DNS)")
    parser.add_argument("--version", action="version", version="packrat 1.0.2")
    parser.add_argument("--nd", action="store_true", help="skip DNS resolution for faster results")
    args = parser.parse_args()

    packets = parse_pcap(args.filepath, skip_dns=args.nd)

    if packets is None:
        return
    
    if len(packets) == 0:
        print("[!] No IP packets found in this capture.")
        return

    # apply filter if provided
    if args.filter:
        f = args.filter.upper()
        packets = [
            pkt for pkt in packets
            if pkt["protocol"].upper() == f
            or pkt["src"] == args.filter
            or pkt["dst"] == args.filter
        ]
        if len(packets) == 0:
            print(f"[!] No packets found matching filter: {args.filter}")
            return
        print(f"[*] Filter applied: {args.filter} — {len(packets)} packets matched")

    results = analyze(packets, skip_dns=args.nd)
    render(results)

    if args.export:
        export(results, args.filepath, args.export)

if __name__ == "__main__":
    main()