import argparse
from packrat.parser import parse_pcap
from packrat.analyzer import analyze
from packrat.renderer import render

def main():
    parser = argparse.ArgumentParser(
        prog="packrat",
        description="🐀 packrat — a clean, human-readable packet analyzer"
    )
    parser.add_argument("filepath", help="path to your .pcap file")
    args = parser.parse_args()

    # run the three steps
    packets = parse_pcap(args.filepath)

    if packets is None:
        return
    
    if len(packets) == 0:
        print("[!] No IP packets found in this capture.")
        return

    results = analyze(packets)
    render(results)

if __name__ == "__main__":
    main()