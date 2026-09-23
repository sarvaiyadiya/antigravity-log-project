"""
ULPF Demo Data Generator — Multi-Format Perimeter Traffic Simulator
====================================================================
Streams continuous realistic multi-format perimeter logs to:
  1. The ULPF Dashboard direct ingest API (http://localhost:7000/api/ingest)
  2. Or the ULPF Live REST Receiver (http://localhost:8080/ingest)
  3. Or appends directly to an output file (outputs/live.jsonl)

Usage:
  # Stream to dashboard server on port 7000 (default)
  python demo/demo_data_generator.py --url http://localhost:7000/api/ingest --delay-ms 50

  # Stream to live REST receiver on port 8080
  python demo/demo_data_generator.py --url http://localhost:8080/ingest --delay-ms 50

  # Append directly to live.jsonl
  python demo/demo_data_generator.py --file outputs/live.jsonl --delay-ms 30
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Diverse realistic perimeter attack and benign event templates
_SAMPLE_TEMPLATES = [
    # 1. Cisco ASA Firewall - Deny TCP
    ("<134>Jan 18 {time} fw01 %ASA-3-106023: Deny tcp src outside:{src_ip}/{src_port} dst inside:{dst_ip}/443 by access-group \"outside_in\" [0x0, 0x0]", "cisco_asa"),
    # 2. Cisco ASA Firewall - Deny UDP
    ("<134>Jan 18 {time} fw01 %ASA-4-106023: Deny udp src outside:{src_ip}/{src_port} dst dmz:{dst_ip}/53 by access-group \"outside_in\" [0x0, 0x0]", "cisco_asa"),
    # 3. Palo Alto PAN-OS - Threat / SQL Injection
    ("1,2024/01/18 {time},001801000001,THREAT,vulnerability,2561,2024/01/18 {time},{src_ip},{dst_ip},0.0.0.0,0.0.0.0,rule-inbound,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,alert-syslog,2024/01/18 {time},{src_port},1,{dst_port},80,0,0,0x0,tcp,alert,\"/login.php?id=1' OR '1'='1\",SQL Injection Attempt(30012),any,high,client-to-server,0,,0.0.0.0,United States", "paloalto"),
    # 4. Palo Alto PAN-OS - Traffic Allow
    ("1,2024/01/18 {time},001801000001,TRAFFIC,drop,2562,2024/01/18 {time},{src_ip},{dst_ip},0.0.0.0,0.0.0.0,rule-perimeter,,,ssl,vsys1,untrust,trust,ethernet1/1,ethernet1/2,syslog,2024/01/18 {time},{src_port},1,{dst_port},443,0,0,0x0,tcp,allow,any,0,0,0,0,0,0,client-to-server,0,,0.0.0.0,Germany", "paloalto"),
    # 5. ArcSight CEF - Firewall Block
    ("CEF:0|Cisco|ASA|9.14|106023|Deny TCP Traffic|7|src={src_ip} spt={src_port} dst={dst_ip} dpt=22 proto=TCP act=Deny msg=Inbound SSH brute force blocked", "cef"),
    # 6. ArcSight CEF - Web Application Attack
    ("CEF:0|Fortinet|FortiGate|7.2|00013|traffic forward deny|8|src={src_ip} spt={src_port} dst={dst_ip} dpt=8080 proto=TCP act=Deny suser=root msg=Command injection detected in URI", "cef"),
    # 7. Snort Fast Alert - Port Scan
    ("01/18-{time}.123456  [**] [1:2001219:20] ET SCAN Potential SSH Brute Force Scan [**] [Classification: Attempted Information Leak] [Priority: 1] {{TCP}} {src_ip}:{src_port} -> {dst_ip}:22", "snort_alert"),
    # 8. Snort Fast Alert - Exploit
    ("01/18-{time}.654321  [**] [1:2019284:3] ET EXPLOIT Remote Code Execution Vulnerability [**] [Classification: Network Trojan Detected] [Priority: 1] {{TCP}} {src_ip}:{src_port} -> {dst_ip}:8080", "snort_alert"),
    # 9. RFC 3164 Syslog - pfSense filterlog pass
    ("<134>Jan 18 {time} perimeter-fw01 filterlog[1204]: 5,,,em0,match,pass,in,4,{src_ip},{dst_ip},{src_port},{dst_port},tcp,flags,S", "syslog"),
    # 10. RFC 5424 Syslog - Perimeter Gateway Deny
    ("<134>1 2024-01-18T{time}.000Z perimeter-gw firewall - - - src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto=TCP action=DENY", "syslog"),
    # 11. IBM QRadar LEEF - Inbound Deny
    ("LEEF:1.0|Cisco|ASA|9.14|106023|src={src_ip}\tspt={src_port}\tdst={dst_ip}\tdpt=443\tproto=TCP\taction=deny\tsev=8", "leef"),
    # 12. Generic JSON - Threat Event
    ("{{\"timestamp\":\"2024-01-18T{time}Z\",\"src_ip\":\"{src_ip}\",\"dst_ip\":\"{dst_ip}\",\"src_port\":{src_port},\"dst_port\":{dst_port},\"protocol\":\"TCP\",\"action\":\"deny\",\"severity\":\"high\",\"threat_name\":\"Cross-Site Scripting Attempt\"}}", "json"),
    # 13. AWS CloudTrail JSON - AccessDenied API Call
    ("{{\"eventVersion\":\"1.08\",\"userIdentity\":{{\"type\":\"IAMUser\",\"userName\":\"recon_user\"}},\"eventTime\":\"2024-01-18T{time}Z\",\"eventSource\":\"iam.amazonaws.com\",\"eventName\":\"ListAccessKeys\",\"sourceIPAddress\":\"{src_ip}\",\"userAgent\":\"aws-cli/2.9.1\",\"errorCode\":\"AccessDenied\"}}", "cloudtrail"),
]

# Attacker and target IP pools
_ATTACKER_IPS = [
    "198.51.100.44", "198.51.100.77", "203.0.113.88", "203.0.113.120",
    "192.0.2.15", "198.51.100.12", "203.0.113.14", "198.51.100.95",
    "198.51.100.110", "203.0.113.250"
]
_TARGET_IPS = [
    "10.0.1.50", "10.0.1.25", "10.0.2.15", "10.0.2.80",
    "172.16.0.10", "192.168.10.5", "10.0.1.100", "10.0.1.20"
]


def load_file_samples() -> list[str]:
    """Load all raw sample lines from tests/samples/ directory."""
    samples_dir = _PROJECT_ROOT / "tests" / "samples"
    lines: list[str] = []
    if samples_dir.exists():
        for p in samples_dir.glob("sample_*.*"):
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        lines.append(stripped)
            except Exception:
                pass
    return lines


def generate_log_line(file_samples: list[str]) -> str:
    """Generate a single formatted perimeter log line."""
    # 70% chance of formatted template, 30% chance of direct file sample line
    if file_samples and random.random() < 0.3:
        return random.choice(file_samples)

    template, _ = random.choice(_SAMPLE_TEMPLATES)
    now = time.localtime()
    time_str = time.strftime("%H:%M:%S", now)
    src_ip = random.choice(_ATTACKER_IPS)
    dst_ip = random.choice(_TARGET_IPS)
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([22, 53, 80, 443, 8080, 8443, 3389])

    return template.format(
        time=time_str,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def send_to_url(url: str, log_line: str) -> bool:
    """Send a log line to an HTTP endpoint via POST."""
    data = log_line.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "text/plain; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status in (200, 201, 202)
    except urllib.error.URLError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="ULPF Multi-Format Perimeter Traffic Simulator")
    parser.add_argument("--url", default="http://localhost:7000/api/ingest", help="Target ingest URL (default: http://localhost:7000/api/ingest)")
    parser.add_argument("--file", default=None, help="Target JSON-Lines output file (e.g. outputs/live.jsonl)")
    parser.add_argument("--delay-ms", type=int, default=50, help="Delay between events in milliseconds (default: 50ms)")
    parser.add_argument("--count", type=int, default=0, help="Total events to send (0 = infinite loop)")
    parser.add_argument("--burst", action="store_true", help="Send events in random bursts")
    args = parser.parse_args()

    file_samples = load_file_samples()

    print("\n" + "=" * 62)
    print("  ULPF Multi-Format Perimeter Traffic Generator")
    print("=" * 62)
    if args.file:
        print(f"  Target File: {args.file}")
    else:
        print(f"  Target URL:  {args.url}")
    print(f"  Delay:       {args.delay_ms} ms (approx {round(1000/max(args.delay_ms, 1), 1)} eps)")
    print(f"  Count:       {'Infinite' if args.count == 0 else args.count}")
    print(f"  Sample pool: {len(file_samples)} file lines loaded")
    print("  Press Ctrl+C to stop.\n")

    sent = 0
    errors = 0
    t0 = time.time()
    file_handle = None

    if args.file:
        p = Path(args.file)
        p.parent.mkdir(parents=True, exist_ok=True)
        file_handle = p.open("a", encoding="utf-8")

    try:
        while True:
            if args.count > 0 and sent >= args.count:
                break

            line = generate_log_line(file_samples)

            if file_handle:
                file_handle.write(line + "\n")
                file_handle.flush()
                sent += 1
            else:
                ok = send_to_url(args.url, line)
                if ok:
                    sent += 1
                else:
                    errors += 1

            if sent % 50 == 0:
                elapsed = max(time.time() - t0, 0.001)
                eps = round(sent / elapsed, 1)
                print(f"[GENERATOR] Sent: {sent} events | Rate: {eps} eps | Errors: {errors}")

            # Sleep delay
            if args.burst and random.random() < 0.1:
                time.sleep(random.uniform(0.3, 0.8))  # Short pause after burst
            else:
                time.sleep(args.delay_ms / 1000.0)

    except KeyboardInterrupt:
        print("\n[GENERATOR] Stopped by user.")
    finally:
        if file_handle:
            file_handle.close()
        elapsed = max(time.time() - t0, 0.001)
        print(f"\n[GENERATOR] Summary: Sent {sent} events in {round(elapsed, 1)}s ({round(sent/elapsed, 1)} eps). Errors: {errors}")


if __name__ == "__main__":
    main()
