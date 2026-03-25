from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

def render(results):
    # header
    console.print(Panel("[bold cyan]packrat 🐀[/bold cyan] — packet analysis results", box=box.ROUNDED))

    # summary stats
    console.print("\n[bold cyan]file summary[/bold cyan]")
    console.print(f"  [dim]total packets[/dim]    {results['total_packets']}")
    console.print(f"  [dim]total data[/dim]       {results['total_bytes'] / 1024:.2f} KB")

    # protocol breakdown
    console.print("\n[bold cyan]protocol breakdown[/bold cyan]")
    for proto, count in results["protocol_counts"].items():
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

    # anomalies
    console.print("[bold cyan]anomalies[/bold cyan]")
    if results["anomalies"]:
        for a in results["anomalies"]:
            console.print(f"  [red]![/red]  {a}")
    else:
        console.print("  [green]✓[/green]  No anomalies detected")

    console.print()