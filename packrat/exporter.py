import json
import os
from datetime import datetime

def export(results, filepath, format):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.splitext(os.path.basename(filepath))[0]
    filename = f"{base}_report_{timestamp}.{format}"

    if format == "json":
        export_json(results, filename)
    elif format == "html":
        export_html(results, filename)
    elif format == "txt":
        export_txt(results, filename)

def export_json(results, filename):
    # convert to serializable format
    clean = {
        "total_packets": results["total_packets"],
        "total_bytes": results["total_bytes"],
        "protocol_counts": results["protocol_counts"],
        "ip_summary": results["ip_summary"],
        "arp": results["arp"],
        "dns": {
            "total": results["dns"]["total"],
            "unique_queries": results["dns"]["unique_queries"],
            "top_queries": results["dns"]["top_queries"],
        },
        "http": {
            "total": results["http"]["total"],
            "top_hosts": results["http"]["top_hosts"],
        },
        "https": results["https"],
        "ssh": results["ssh"],
        "ftp": results["ftp"],
        "smtp": results["smtp"],
        "imap": results["imap"],
        "anomalies": results["anomalies"],
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=4)

    print(f"\n🐀 report saved to {filename}")

def export_html(results, filename):
    anomaly_rows = ""
    for a in results["anomalies"]:
        anomaly_rows += f'<tr><td class="red">! {a}</td></tr>'
    if not anomaly_rows:
        anomaly_rows = '<tr><td class="green">✓ No anomalies detected</td></tr>'

    ip_rows = ""
    for ip in results["ip_summary"]:
        total = ip["sent"] + ip["received"]
        ip_rows += f"<tr><td>{ip['ip']}</td><td>{ip['sent']}</td><td>{ip['received']}</td><td>{total}</td></tr>"

    dns_rows = ""
    for domain, count in results["dns"]["top_queries"]:
        dns_rows += f"<tr><td>{domain}</td><td>{count}</td></tr>"

    proto_rows = ""
    for proto, count in sorted(results["protocol_counts"].items(), key=lambda x: x[1], reverse=True):
        percent = (count / results["total_packets"]) * 100
        proto_rows += f"<tr><td>{proto}</td><td>{count}</td><td>{percent:.1f}%</td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>packrat 🐀 report</title>
    <style>
        body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
        h1 {{ color: #79c0ff; }}
        h2 {{ color: #79c0ff; margin-top: 2rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th {{ text-align: left; color: #8b949e; padding: 8px; border-bottom: 1px solid #30363d; }}
        td {{ padding: 8px; border-bottom: 1px solid #21262d; }}
        .red {{ color: #f85149; }}
        .green {{ color: #56d364; }}
        .summary p {{ margin: 4px 0; }}
        .dim {{ color: #8b949e; }}
    </style>
</head>
<body>
    <h1>packrat 🐀 — packet analysis report</h1>
    <div class="summary">
        <h2>file summary</h2>
        <p><span class="dim">total packets</span> &nbsp; {results['total_packets']}</p>
        <p><span class="dim">total data</span> &nbsp; {results['total_bytes'] / 1024:.2f} KB</p>
    </div>

    <h2>protocol breakdown</h2>
    <table>
        <tr><th>protocol</th><th>packets</th><th>percent</th></tr>
        {proto_rows}
    </table>

    <h2>top ip addresses</h2>
    <table>
        <tr><th>ip address</th><th>sent</th><th>received</th><th>total</th></tr>
        {ip_rows}
    </table>

    <h2>dns — top domains queried</h2>
    <table>
        <tr><th>domain</th><th>queries</th></tr>
        {dns_rows}
    </table>

    <h2>anomalies</h2>
    <table>
        {anomaly_rows}
    </table>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n🐀 report saved to {filename}")


def export_txt(results, filename):
    lines = []
    lines.append("packrat 🐀 — packet analysis report")
    lines.append("=" * 50)

    lines.append("\nfile summary")
    lines.append(f"  total packets    {results['total_packets']}")
    lines.append(f"  total data       {results['total_bytes'] / 1024:.2f} KB")

    lines.append("\nprotocol breakdown")
    for proto, count in sorted(results["protocol_counts"].items(), key=lambda x: x[1], reverse=True):
        percent = (count / results["total_packets"]) * 100
        bar = "█" * int(percent / 5)
        lines.append(f"  {proto:<8} {bar:<20} {percent:.1f}%")

    lines.append("\ntop ip addresses")
    lines.append(f"  {'ip address':<25} {'sent':>10} {'received':>10} {'total':>10}")
    lines.append("  " + "-" * 55)
    for ip in results["ip_summary"]:
        total = ip["sent"] + ip["received"]
        lines.append(f"  {ip['ip']:<25} {ip['sent']:>10} {ip['received']:>10} {total:>10}")

    if results["dns"]["total"] > 0:
        lines.append("\ndns activity")
        lines.append(f"  total           {results['dns']['total']} packets")
        lines.append(f"  unique queries  {results['dns']['unique_queries']}")
        if results["dns"]["top_queries"]:
            lines.append("\n  top domains queried")
            for domain, count in results["dns"]["top_queries"]:
                lines.append(f"    {domain:<40} {count} queries")

    if results["http"]["total"] > 0:
        lines.append("\nhttp activity")
        lines.append(f"  total   {results['http']['total']} packets")
        if results["http"]["top_hosts"]:
            lines.append("\n  top hosts visited")
            for host, count in results["http"]["top_hosts"]:
                lines.append(f"    {host:<40} {count} requests")

    if results["https"]["total"] > 0:
        lines.append("\nhttps/tls activity")
        lines.append(f"  total           {results['https']['total']} packets")
        lines.append(f"  tls handshakes  {results['https']['tls_handshakes']}")

    if results["ssh"]["total"] > 0:
        lines.append("\nssh activity")
        lines.append(f"  total   {results['ssh']['total']} packets")

    if results["ftp"]["total"] > 0:
        lines.append("\nftp activity")
        lines.append(f"  total   {results['ftp']['total']} packets")

    if results["smtp"]["total"] > 0:
        lines.append("\nsmtp activity")
        lines.append(f"  total   {results['smtp']['total']} packets")

    if results["imap"]["total"] > 0:
        lines.append("\nimap activity")
        lines.append(f"  total   {results['imap']['total']} packets")

    lines.append("\nanomalies")
    if results["anomalies"]:
        for a in results["anomalies"]:
            lines.append(f"  ! {a}")
    else:
        lines.append("  ✓ No anomalies detected")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n🐀 report saved to {filename}")