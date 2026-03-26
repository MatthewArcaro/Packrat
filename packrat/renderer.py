from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

def render(results):
    # header
    console.print(Panel("[bold cyan]packrat 🐀[/bold cyan] — packet analysis results", box=box.ROUNDED))

    # file summary
    console.print("\n[bold cyan]file summary[/bold cyan]")
    console.print(f"  [dim]total packets[/dim]    {results['total_packets']}")
    console.print(f"  [dim]total data[/dim]       {results['total_bytes'] / 1024:.2f} KB")

    # protocol breakdown
    console.print("\n[bold cyan]protocol breakdown[/bold cyan]")
    for proto, count in sorted(results["protocol_counts"].items(), key=lambda x: x[1], reverse=True):
        percent = (count / results["total_packets"]) * 100
        bar = "█" * int(percent / 5)
        console.print(f"  [dim]{proto:<8}[/dim] [green]{bar:<20}[/green] {percent:.1f}%")

    # top IPs table
    console.print("\n[bold cyan]top ip addresses[/bold cyan]")
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    table.add_column("ip address", style="green")
    table.add_column("pkts sent", justify="right")
    table.add_column("pkts received", justify="right")
    table.add_column("total", justify="right", style="cyan")
    for ip in results["ip_summary"]:
        table.add_row(
            ip["ip"],
            str(ip["sent"]),
            str(ip["received"]),
            str(ip["sent"] + ip["received"])
        )
    console.print(table)

    # ARP summary
    arp = results["arp"]
    if arp["total"] > 0:
        console.print("[bold cyan]arp activity[/bold cyan]")
        console.print(f"  [dim]total[/dim]       {arp['total']} packets")
        console.print(f"  [dim]requests[/dim]    {arp['requests']}")
        console.print(f"  [dim]replies[/dim]     {arp['replies']}")

    # DNS summary
    dns = results["dns"]
    if dns["total"] > 0:
        console.print("\n[bold cyan]dns activity[/bold cyan]")
        console.print(f"  [dim]total[/dim]           {dns['total']} packets")
        console.print(f"  [dim]unique queries[/dim]  {dns['unique_queries']}")
        if dns["top_queries"]:
            console.print(f"\n  [dim]top domains queried[/dim]")
            for domain, count in dns["top_queries"]:
                console.print(f"    [green]{domain:<40}[/green] {count} queries")

    # HTTP summary
    http = results["http"]
    if http["total"] > 0:
        console.print("\n[bold cyan]http activity[/bold cyan]")
        console.print(f"  [dim]total[/dim]   {http['total']} packets")
        if http["top_hosts"]:
            console.print(f"\n  [dim]top hosts visited[/dim]")
            for host, count in http["top_hosts"]:
                console.print(f"    [green]{host:<40}[/green] {count} requests")

    # HTTPS summary
    https = results["https"]
    if https["total"] > 0:
        console.print("\n[bold cyan]https/tls activity[/bold cyan]")
        console.print(f"  [dim]total[/dim]           {https['total']} packets")
        console.print(f"  [dim]tls handshakes[/dim]  {https['tls_handshakes']}")

    # SSH summary
    ssh = results["ssh"]
    if ssh["total"] > 0:
        console.print("\n[bold cyan]ssh activity[/bold cyan]")
        console.print(f"  [dim]total[/dim]   {ssh['total']} packets")

    # FTP summary
    ftp = results["ftp"]
    if ftp["total"] > 0:
        console.print("\n[bold cyan]ftp activity[/bold cyan]")
        console.print(f"  [dim]total[/dim]   {ftp['total']} packets")

    # SMTP summary
    smtp = results["smtp"]
    if smtp["total"] > 0:
        console.print("\n[bold cyan]smtp activity[/bold cyan]")
        console.print(f"  [dim]total[/dim]   {smtp['total']} packets")

    # IMAP summary
    imap = results["imap"]
    if imap["total"] > 0:
        console.print("\n[bold cyan]imap activity[/bold cyan]")
        console.print(f"  [dim]total[/dim]   {imap['total']} packets")

    # anomalies
    console.print("\n[bold cyan]anomalies[/bold cyan]")
    if results["anomalies"]:
        for a in results["anomalies"]:
            console.print(f"  [red]![/red]  {a}")
    else:
        console.print("  [green]✓[/green]  No anomalies detected")

    console.print()