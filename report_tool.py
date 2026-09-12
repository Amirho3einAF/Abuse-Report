import requests
import re
import socket
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
console = Console()
def check_dnsbl(ip):
    dnsbl_services = ["zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net"]
    reversed_ip = ".".join(reversed(ip.split(".")))
    listed_count = 0
    for bl in dnsbl_services:
        try:
            query = f"{reversed_ip}.{bl}"
            socket.gethostbyname(query)
            listed_count += 1
        except socket.gaierror:
            continue
    if listed_count == 0:
        return "[bold green]Clean (0/3 Blacklists)[/bold green]"
    else:
        return f"[bold red]Malicious! (Flagged in {listed_count}/3 Blacklists)[/bold red]"
def generate_abuse_report(ip_address):
    with console.status(f"[bold cyan]Analyzing Target IP: {ip_address}...[/bold cyan]", spinner="bouncingBar"):
        reputation_status = check_dnsbl(ip_address)
        try:
            ipinfo_resp = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10).json()
            asn = ipinfo_resp.get("org", "N/A") 
            geo_location = f"{ipinfo_resp.get('city', 'Unknown')}, {ipinfo_resp.get('country', 'Unknown')}"
        except Exception:
            asn, geo_location = "Error", "Error"
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
            response = requests.get(f"https://rdap.org/ip/{ip_address}", headers=headers, timeout=10)
            if response.status_code != 200:
                adversary_email = f"HTTP Error: {response.status_code}"
            else:
                rdap_resp = response.json()
                adversary_email = "N/A"
                if "entities" in rdap_resp:
                    for entity in rdap_resp["entities"]:
                        if "roles" in entity and "abuse" in entity["roles"]:
                            if "vcardArray" in entity:
                                for vcard_item in entity["vcardArray"][1]:
                                    if vcard_item[0] == "email":
                                        adversary_email = vcard_item[3]
                                        break
                if adversary_email == "N/A":
                    text_dump = str(rdap_resp)
                    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text_dump)
                    abuse_emails = list(set([e for e in emails if 'abuse' in e.lower()]))
                    if abuse_emails:
                        adversary_email = abuse_emails[0]
                    elif emails:
                        adversary_email = list(set(emails))[0]
        except Exception:
            adversary_email = "Connection/Parse Error"
    table = Table(show_header=True, header_style="bold blue", border_style="cyan")
    table.add_column("Field", style="cyan", width=25)
    table.add_column("Extracted Data", style="white")
    table.add_row("Blacklist Status", reputation_status)
    table.add_row("Adversary Geo Location", geo_location)
    table.add_row("ASN / ISP", asn)
    if "@" in adversary_email:
        table.add_row("Adversary Email", f"[bold red]{adversary_email}[/bold red]")
    else:
        table.add_row("Adversary Email", f"[bold yellow]{adversary_email}[/bold yellow]")
    console.print(Panel(table, title=f"[bold blue]Threat Intel Report: {ip_address}[/bold blue]", expand=False))
if __name__ == "__main__":
    console.clear()
    console.print("[bold green]=== SOC IP Abuse Report Tool ===[/bold green]")
    console.print("[dim]Type 'exit' or 'quit' to close the program.[/dim]\n")
    while True:
        target_ip = Prompt.ask("\n[bold yellow]Enter Target IP[/bold yellow]")
        if target_ip.lower() in ['exit', 'quit', 'q']:
            console.print("[bold red]Exiting tool... Stay secure![/bold red]")
            break
        if not target_ip.strip():
            continue
        generate_abuse_report(target_ip.strip())