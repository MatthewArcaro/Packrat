import argparse
import os
from rich.console import Console
from packrat.core.parser import parse_pcap
from packrat.core.analyzer import analyze
from packrat.cli.renderer import render
from packrat.core.exporter import export
from packrat.detection.ddos import detect
console = Console()

def main():
    parser = argparse.ArgumentParser(
        prog="packrat",
        description="🐀 packrat — a clean, human-readable packet analyzer"
    )
    parser.add_argument("filepath", help="path to your .pcap file")
    parser.add_argument("--export", choices=["json", "html", "txt"], help="export results to a file")
    parser.add_argument("--filter", help="filter by IP address or protocol (e.g. 10.2.28.88 or DNS)")
    parser.add_argument("--version", action="version", version="packrat 1.1.3")
    parser.add_argument("--nd", action="store_true", help="skip DNS resolution for faster results")
    args = parser.parse_args()

    console.print(f"🐀 Loading [cyan]{os.path.basename(args.filepath)}[/cyan] into memory...")

    packets, error = parse_pcap(args.filepath, skip_dns=args.nd)

    if error:
        console.print(f"[red]{error}[/red]")
        return

    if len(packets) == 0:
        console.print("[red][!] No IP packets found in this capture.[/red]")
        return

    if args.nd:
        console.print(f"[green]Parsed {len(packets)} packets successfully![/green]")
    else:
        console.print(f"[green]Parsed {len(packets)} packets successfully![/green] Doing DNS resolution... (skip with --nd)")

    if args.filter:
        f = args.filter.upper()
        packets = [
            pkt for pkt in packets
            if pkt["protocol"].upper() == f
            or pkt["src"] == args.filter
            or pkt["dst"] == args.filter
        ]
        if len(packets) == 0:
            console.print(f"[red][!] No packets found matching filter: {args.filter}[/red]")
            return
        console.print(f"[cyan][*] Filter applied: {args.filter} — {len(packets)} packets matched[/cyan]")

    results = analyze(packets, skip_dns=args.nd)
    detections = detect(packets)
    render(results, detections)

    if args.export:
        export(results, args.filepath, args.export)

if __name__ == "__main__":
    main()