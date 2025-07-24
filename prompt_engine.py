# prompt_engine.py

import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Initialize OpenRouter client
client = OpenAI(
    api_key=os.getenv("DEEPSEEK_API_KEY"),
    base_url="https://openrouter.ai/api/v1",
    default_headers={
        "HTTP-Referer": "https://yourprojectname.com",  # Optional
        "X-Title": "PCAP Forensics Assistant",  # Optional
    },
)


def build_prompt(events):
    if not events:
        return "No events to analyze."

    IGNORE_PROTOCOLS = {"ARP", "SSDP", "ICMP", "NBNS", "MDNS"}

    timeline_lines = []
    dns_queries = set()
    suspicious_packets = []

    for evt in events:
        if evt.get("Protocol") in IGNORE_PROTOCOLS:
            continue

        src_ip = evt.get("Src IP")
        dst_ip = evt.get("Dst IP")
        src_port = evt.get("Src Port")
        dst_port = evt.get("Dst Port")

        if not (src_ip and dst_ip and src_port and dst_port):
            continue  # skip incomplete packets

        # Track DNS Queries
        if evt.get("DNS Query"):
            dns_queries.add(evt["DNS Query"])

        # Heuristic suspicious detection
        info_lower = evt.get("Info", "").lower()
        if any(
            keyword in info_lower
            for keyword in [
                "authenticator",
                "login",
                "token",
                ".exe",
                "google",
                "download",
                "setup",
                "security",
                "password",
                "verify",
                "patch",
                "update",
                ".zip",
                ".xyz",
                ".click",
                ".lol",
                "secure",
                ".scr",
                ".bat",
                ".jar",
                ".vbs",
            ]
        ) or evt.get("LDAP Malformed"):
            suspicious_packets.append(evt)

        # Build timeline entry with new fields
        line = f"[#{evt.get('No')}] {evt.get('Timestamp')} | {evt.get('Protocol')} | {src_ip}:{src_port} ➤ {dst_ip}:{dst_port}"

        if evt.get("DNS Query"):
            line += f" | DNS Query: {evt['DNS Query']}"

        if evt.get("DNS Query Type"):
            line += f" (Type: {evt['DNS Query Type']})"

        if evt.get("HTTP Host"):
            line += f" | HTTP Host: {evt['HTTP Host']}"

        if evt.get("HTTP URI"):
            line += f" | HTTP URI: {evt['HTTP URI']}"

        if evt.get("TLS SNI"):
            line += f" | TLS SNI: {evt['TLS SNI']}"

        if evt.get("LDAP Malformed"):
            line += " | LDAP Malformed: True"

        line += f" | Info: {evt.get('Info')}"
        timeline_lines.append(line)

    # Rough token estimation (1 token ≈ 4 characters)
    max_chars = 100000  # ~25k tokens for timeline
    current_chars = 0
    limited_lines = []

    for line in timeline_lines:
        if current_chars + len(line) > max_chars:
            break
        limited_lines.append(line)
        current_chars += len(line)

    timeline = "\n".join(limited_lines)

    # DNS Summary
    dns_summary = "\n".join(f"- {q}" for q in sorted(dns_queries))

    # Suspicious packet overview
    suspicious_summary = "\n".join(
        f"[#{pkt['No']}] {pkt.get('Protocol')} ➤ {pkt.get('Info')[:150]}..."
        for pkt in suspicious_packets
    )

    return (
        "You are a senior SOC analyst with expertise in malware analysis and network forensics.\n\n"
        "Your task is to analyze this timeline of events extracted from a PCAP file. Carefully examine:\n"
        "- Suspicious or malicious IP addresses.\n"
        "- Suspicious domain names (check DNS queries, known C2 domains, or typo-squatting).\n"
        "- Signs of malware communication, exfiltration, lateral movement, or port scanning.\n"
        "- Any indicators of compromise (IOCs), and\n"
        "- Provide actionable recommendations for mitigation and network hardening.\n\n"
        "Important:\n"
        "- Mention exact frames/packet numbers and timestamps if available.\n"
        "- Correlate multiple events when possible.\n"
        "- Make the response structured: Summary ➤ IOCs ➤ Threat Assessment ➤ Recommendations.\n\n"
        "=== Top DNS Queries Observed ===\n"
        f"{dns_summary if dns_summary else 'No DNS queries observed.'}\n\n"
        "=== Suspicious Packet Highlights ===\n"
        f"{suspicious_summary if suspicious_summary else 'No obviously suspicious packets found.'}\n\n"
        "=== Timeline ===\n"
        f"{timeline}"
    )


def ask_ai(prompt):
    try:
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1-0528:free",
            messages=[
                {
                    "role": "system",
                    "content": "You are a SOC analyst skilled at detecting malicious activity in network logs.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=6000,
        )

        if response and response.choices:
            return response.choices[0].message.content
        else:
            return "[ERROR] AI response was empty or malformed."

    except Exception as e:
        return f"[ERROR] Exception during AI request: {e}"
