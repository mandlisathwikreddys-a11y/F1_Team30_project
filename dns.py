#!/usr/bin/env python3
"""
NetCheck - All-in-One Domain Checker
Enter a domain name and get a full report: DNS, IP Info, Ping, HTTP, Whois, SSL, Blacklist.
No menus. No choices. Just enter domain and get everything.
"""

import socket
import ssl
import json
import time
import urllib.request
import urllib.error
import http.client
import os
import sys
import platform
import subprocess
import datetime

# ─── ANSI Colors ───────────────────────────────────────────────────────────────
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"


def c(text, color):
    return f"{color}{text}{Colors.RESET}"


def banner():
    print()
    print(c("  ╔══════════════════════════════════════════════════════════════╗", Colors.CYAN))
    print(c("  ║           NetCheck - All-in-One Domain Checker              ║", Colors.CYAN))
    print(c("  ║     DNS | IP Info | Ping | HTTP | Whois | SSL | Blacklist   ║", Colors.CYAN))
    print(c("  ╚══════════════════════════════════════════════════════════════╝", Colors.CYAN))
    print()


def print_section(num, title):
    print()
    print(c(f"  ┌─── {num}. {title} ", Colors.MAGENTA) + c("─" * max(1, 55 - len(title)), Colors.DIM))
    print(c("  │", Colors.DIM))


def print_kv(key, value, value_color=None):
    val = c(str(value), value_color) if value_color else str(value)
    print(c("  │  ", Colors.DIM) + c(f"{key}:", Colors.BOLD) + f" {val}")


def print_footer():
    print(c("  └" + "─" * 58, Colors.DIM))


def print_error(msg):
    print(c(f"  │  ✗ {msg}", Colors.RED))


def print_success(msg):
    print(c(f"  │  ✓ {msg}", Colors.GREEN))


def print_info(msg):
    print(c(f"  │  ℹ {msg}", Colors.BLUE))


def print_warning(msg):
    print(c(f"  │  ⚠ {msg}", Colors.YELLOW))


def separator():
    print(c("  │", Colors.DIM))


# ─── DNS LOOKUP ────────────────────────────────────────────────────────────────
DNS_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257
}
TYPE_NAMES = {v: k for k, v in DNS_TYPES.items()}


def check_dns(domain):
    print_section("01", "DNS Records")
    results = {}
    try:
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
            url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={DNS_TYPES[rtype]}"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            answers = data.get("Answer", [])
            if answers:
                results[rtype] = answers
    except Exception as e:
        print_error(f"DNS query failed: {e}")
        print_footer()
        return

    if not results:
        print_warning("No DNS records found for this domain.")
        print_footer()
        return

    for rtype, records in results.items():
        print(c(f"  │  ", Colors.DIM) + c(f"{rtype} Records", Colors.YELLOW) + c(f" ({len(records)})", Colors.DIM))
        for rec in records:
            ttl = rec.get("TTL", "?")
            data_val = rec.get("data", "?")
            print(c("  │    ", Colors.DIM) + f"[TTL: {ttl}s]  {c(data_val, Colors.GREEN)}")
        separator()

    print_footer()


# ─── IP INFO ───────────────────────────────────────────────────────────────────
def check_ip_info(domain):
    print_section("02", "IP Info & Geolocation")
    try:
        ip = socket.gethostbyname(domain)
        print_kv("Resolved IP", ip, Colors.GREEN)

        url = f"https://ipwho.is/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "NetCheck/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        if not data.get("success"):
            print_error(data.get("message", "Lookup failed."))
            print_footer()
            return

        print_kv("IP Address", data.get("ip", "N/A"), Colors.GREEN)
        print_kv("Type", data.get("type", "N/A"))
        print_kv("Country", f"{data.get('country', 'N/A')} ({data.get('country_code', '')})", Colors.GREEN)
        print_kv("Region", data.get("region", "N/A"))
        print_kv("City", data.get("city", "N/A"))
        print_kv("Postal Code", data.get("postal", "N/A"))
        print_kv("Timezone", data.get("timezone", "N/A"))
        print_kv("ISP", data.get("connection", {}).get("isp", "N/A"))
        print_kv("Organization", data.get("connection", {}).get("org", "N/A"))
        print_kv("ASN", data.get("connection", {}).get("asn", "N/A"))
        print_footer()

    except socket.gaierror:
        print_error(f"Could not resolve {domain}")
        print_footer()
    except Exception as e:
        print_error(f"Error: {e}")
        print_footer()


# ─── PING ──────────────────────────────────────────────────────────────────────
def check_ping(domain):
    print_section("03", "Ping Check")
    try:
        ip = socket.gethostbyname(domain)
        print_kv("Resolved IP", ip)
    except socket.gaierror:
        print_error(f"Could not resolve {domain}")
        print_footer()
        return

    param = "-n" if platform.system().lower() == "windows" else "-c"
    times = []

    for i in range(4):
        try:
            start = time.time()
            result = subprocess.run(
                ["ping", param, "1", "-W", "3", domain],
                capture_output=True, text=True, timeout=10
            )
            elapsed = (time.time() - start) * 1000
            if result.returncode == 0:
                times.append(elapsed)
                print(c(f"  │  ", Colors.DIM) + c(f"[{i+1}]", Colors.CYAN) + f" {c('OK', Colors.GREEN)} — {elapsed:.0f} ms")
            else:
                print(c(f"  │  ", Colors.DIM) + c(f"[{i+1}]", Colors.CYAN) + f" {c('FAIL', Colors.RED)} — no response")
        except subprocess.TimeoutExpired:
            print(c(f"  │  ", Colors.DIM) + c(f"[{i+1}]", Colors.CYAN) + f" {c('TIMEOUT', Colors.YELLOW)}")
        except FileNotFoundError:
            print_error("ping command not found on this system.")
            print_footer()
            return

    separator()
    if times:
        avg = sum(times) / len(times)
        mn = min(times)
        mx = max(times)
        lost = 4 - len(times)
        loss_pct = (lost / 4) * 100

        print_kv("Packets Sent", "4")
        print_kv("Received", str(len(times)), Colors.GREEN)
        print_kv("Lost", str(lost), Colors.RED if lost > 0 else Colors.GREEN)
        print_kv("Packet Loss", f"{loss_pct:.0f}%", Colors.RED if loss_pct > 50 else Colors.YELLOW if loss_pct > 0 else Colors.GREEN)
        print_kv("Min Time", f"{mn:.0f} ms")
        print_kv("Avg Time", f"{avg:.0f} ms", Colors.GREEN if avg < 100 else Colors.YELLOW if avg < 200 else Colors.RED)
        print_kv("Max Time", f"{mx:.0f} ms")

        if avg < 50:
            print_success("Rating: Excellent!")
        elif avg < 100:
            print_success("Rating: Good")
        elif avg < 200:
            print_warning("Rating: Okay")
        else:
            print_error("Rating: Slow")
    else:
        print_error("All pings failed. Host may be offline or blocking ping.")

    print_footer()


# ─── HTTP CHECK ────────────────────────────────────────────────────────────────
def check_http(domain):
    print_section("04", "HTTP Headers Check")
    url = f"https://{domain}"

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        path = parsed.path or "/"

        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=10, context=ctx)

        start = time.time()
        conn.request("GET", path, headers={"User-Agent": "NetCheck/1.0"})
        resp = conn.getresponse()
        elapsed = (time.time() - start) * 1000
        conn.close()

        status = resp.status
        status_text = resp.reason

        if 200 <= status < 300:
            status_color = Colors.GREEN
        elif 300 <= status < 400:
            status_color = Colors.YELLOW
        else:
            status_color = Colors.RED

        print_kv("URL", url, Colors.GREEN)
        print_kv("Status", f"{status} {status_text}", status_color)
        print_kv("Response Time", f"{elapsed:.0f} ms")
        print_kv("Server", resp.getheader("Server", "N/A"))
        print_kv("Content-Type", resp.getheader("Content-Type", "N/A"))
        print_kv("Content-Length", resp.getheader("Content-Length", "N/A"))
        print_kv("Connection", resp.getheader("Connection", "N/A"))
        print_kv("Cache-Control", resp.getheader("Cache-Control", "N/A"))

        separator()
        print(c("  │  ", Colors.DIM) + c("Security Headers:", Colors.BOLD))

        sec_headers = {
            "Strict-Transport-Security": "Forces HTTPS connections",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "X-Frame-Options": "Prevents clickjacking",
            "Content-Security-Policy": "Controls resource loading",
            "X-XSS-Protection": "Built-in XSS filter",
        }
        for header, desc in sec_headers.items():
            val = resp.getheader(header)
            if val:
                print_success(f"{header}: {val}")
            else:
                print_warning(f"{header}: Not set")

        separator()
        print(c("  │  ", Colors.DIM) + c("All Response Headers:", Colors.BOLD))
        for key, val in resp.getheaders():
            print(c("  │    ", Colors.DIM) + c(key + ":", Colors.CYAN) + f" {val}")

        print_footer()

    except Exception as e:
        print_error(f"HTTP check failed: {e}")
        print_footer()


# ─── WHOIS ─────────────────────────────────────────────────────────────────────
def check_whois(domain):
    print_section("05", "Whois Lookup")
    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(
            rdap_url,
            headers={"User-Agent": "NetCheck/1.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        print_kv("Domain", data.get("ldhName", "N/A"), Colors.GREEN)

        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "N/A")
            if action == "registration":
                print_kv("Registered", date, Colors.GREEN)
            elif action == "expiration":
                print_kv("Expires", date, Colors.YELLOW)
            elif action == "last update":
                print_kv("Last Updated", date)

        ns_list = data.get("nameservers", [])
        if ns_list:
            names = ", ".join(ns.get("ldhName", "") for ns in ns_list)
            print_kv("Name Servers", names)

        status = data.get("status", [])
        if status:
            print_kv("Status", ", ".join(status))

        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            print_kv("Registrar", item[3])

        print_footer()

    except urllib.error.HTTPError as e:
        print_error(f"Domain not found or RDAP error (HTTP {e.code}).")
        print_footer()
    except Exception as e:
        print_error(f"Error: {e}")
        print_footer()


# ─── SSL CHECK ─────────────────────────────────────────────────────────────────
def check_ssl(domain):
    print_section("06", "SSL Certificate Check")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        print_success(f"SSL certificate is valid for {domain}!")
        separator()
        print_kv("Domain", subject.get("commonName", "N/A"))
        print_kv("Issuer", issuer.get("organizationName", "N/A"))
        print_kv("Valid From", cert.get("notBefore", "N/A"))
        print_kv("Valid Until", cert.get("notAfter", "N/A"), Colors.YELLOW)

        try:
            expiry = datetime.datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 0:
                print_kv("Days Left", "EXPIRED", Colors.RED)
            elif days_left < 30:
                print_kv("Days Left", f"{days_left} days", Colors.RED)
            else:
                print_kv("Days Left", f"{days_left} days", Colors.GREEN)
        except ValueError:
            pass

        print_kv("TLS Version", version, Colors.GREEN)
        print_kv("Cipher", cipher[0], Colors.GREEN)

        san = cert.get("subjectAltName", [])
        if san:
            print_kv("Alt Names", f"{len(san)} domains")
            for typ, name in san[:5]:
                print(c("  │      - ", Colors.DIM) + name)
            if len(san) > 5:
                print(c("  │      ... and ", Colors.DIM) + str(len(san) - 5) + " more")

        print_footer()

    except ssl.SSLCertVerificationError as e:
        print_error(f"SSL certificate verification failed: {e}")
        print_warning("The certificate may be expired, self-signed, or invalid.")
        print_footer()
    except socket.timeout:
        print_error("Connection timed out.")
        print_footer()
    except socket.gaierror:
        print_error(f"Could not resolve {domain}")
        print_footer()
    except ConnectionRefusedError:
        print_error(f"Connection refused. {domain} may not support HTTPS on port 443.")
        print_footer()
    except Exception as e:
        print_error(f"Error: {e}")
        print_footer()


# ─── BLACKLIST CHECK ───────────────────────────────────────────────────────────
BLACKLIST_ZONES = [
    ("zen.spamhaus.org", "Spamhaus"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("cbl.abuseat.org", "CBL"),
    ("pbl.spamhaus.org", "PBL"),
    ("xbl.spamhaus.org", "XBL"),
    ("dnsbl-1.uceprotect.net", "UCEProtect"),
]


def check_blacklist(domain):
    print_section("07", "Blacklist Check")
    try:
        ip = socket.gethostbyname(domain)
        print_kv("IP Address", ip)
    except socket.gaierror:
        print_error(f"Could not resolve {domain}")
        print_footer()
        return

    reversed_ip = ".".join(reversed(ip.split(".")))
    separator()

    listed = []
    not_listed = []

    for zone, name in BLACKLIST_ZONES:
        try:
            query = f"{reversed_ip}.{zone}"
            answers = socket.getaddrinfo(query, None)
            if answers:
                listed.append((zone, name))
                print(c(f"  │  ", Colors.DIM) + c("✗ LISTED", Colors.RED) + f"   — {zone} ({name})")
            else:
                not_listed.append(zone)
                print(c(f"  │  ", Colors.DIM) + c("✓ Clean", Colors.GREEN) + f"    — {zone}")
        except socket.gaierror:
            not_listed.append(zone)
            print(c(f"  │  ", Colors.DIM) + c("✓ Clean", Colors.GREEN) + f"    — {zone}")
        except Exception as e:
            print(c(f"  │  ", Colors.DIM) + c("? Error", Colors.YELLOW) + f"   — {zone}: {e}")

    separator()
    if listed:
        print_error(f"IP {ip} is listed on {len(listed)} blacklist(s)!")
        print_warning("If this is your server's IP, your emails may go to spam.")
    else:
        print_success(f"IP {ip} is clean — not found on any checked blacklist.")

    print_footer()


# ─── SUMMARY ───────────────────────────────────────────────────────────────────
def print_summary(domain, results):
    print()
    print(c("  ╔══════════════════════════════════════════════════════════════╗", Colors.CYAN))
    print(c("  ║                    CHECK SUMMARY                             ║", Colors.CYAN))
    print(c("  ╚══════════════════════════════════════════════════════════════╝", Colors.CYAN))
    print()
    print(f"  Domain: {c(domain, Colors.BOLD)}")
    print()

    total = len(results)
    passed = sum(1 for v in results.values() if v == "PASS")
    failed = sum(1 for v in results.values() if v == "FAIL")
    warning = sum(1 for v in results.values() if v == "WARN")

    for check, status in results.items():
        if status == "PASS":
            icon = c("✓", Colors.GREEN)
            label = c("PASS", Colors.GREEN)
        elif status == "FAIL":
            icon = c("✗", Colors.RED)
            label = c("FAIL", Colors.RED)
        else:
            icon = c("⚠", Colors.YELLOW)
            label = c("WARN", Colors.YELLOW)
        print(f"    {icon} {check:<20} {label}")

    print()
    print(f"  Total: {total}  |  {c('Passed: ' + str(passed), Colors.GREEN)}  |  {c('Failed: ' + str(failed), Colors.RED)}  |  {c('Warnings: ' + str(warning), Colors.YELLOW)}")
    print()


# ─── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    banner()

    domain = input(c("  Enter domain name (e.g., google.com): ", Colors.BOLD)).strip()

    if not domain:
        print_error("No domain entered. Exiting.")
        sys.exit(1)

    if "." not in domain or len(domain) < 4:
        print_error("Invalid domain name. Please enter a valid domain like google.com")
        sys.exit(1)

    print()
    print(c("  ════════════════════════════════════════════════════════════", Colors.DIM))
    print(c("  Starting full check for: ", Colors.DIM) + c(domain, Colors.BOLD))
    print(c("  ════════════════════════════════════════════════════════════", Colors.DIM))

    results = {}

    try:
        check_dns(domain)
        results["DNS Records"] = "PASS"
    except Exception:
        results["DNS Records"] = "FAIL"

    try:
        check_ip_info(domain)
        results["IP Info"] = "PASS"
    except Exception:
        results["IP Info"] = "FAIL"

    try:
        check_ping(domain)
        results["Ping"] = "PASS"
    except Exception:
        results["Ping"] = "FAIL"

    try:
        check_http(domain)
        results["HTTP Check"] = "PASS"
    except Exception:
        results["HTTP Check"] = "FAIL"

    try:
        check_whois(domain)
        results["Whois"] = "PASS"
    except Exception:
        results["Whois"] = "FAIL"

    try:
        check_ssl(domain)
        results["SSL Certificate"] = "PASS"
    except Exception:
        results["SSL Certificate"] = "FAIL"

    try:
        check_blacklist(domain)
        results["Blacklist"] = "PASS"
    except Exception:
        results["Blacklist"] = "FAIL"

    print_summary(domain, results)

    print(c("  ──────────────────────────────────────────────────────────────", Colors.DIM))
    print(c("  Check complete! Thanks for using NetCheck.", Colors.GREEN))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print(c("\n  Interrupted. Goodbye!", Colors.YELLOW))
        sys.exit(0)
