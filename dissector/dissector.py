from scapy.all import rdpcap, IP, TCP, Raw
import json
import re

def parse_http_payload(payload: bytes):
    """
    Try to parse HTTP request payload into structured fields.
    Returns dict or None if not HTTP.
    """
    try:
        text = payload.decode(errors="ignore")
    except:
        return None

    lines = text.split("\r\n")
    if not lines or len(lines[0].split()) < 2:
        return None

    # Detect HTTP request line: e.g. "POST /login HTTP/1.1"
    first_line = lines[0]
    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)", first_line)
    if not match:
        return None

    method, endpoint = match.groups()
    headers = {}
    body = None
    parsing_headers = True

    for line in lines[1:]:
        if line == "":  # end of headers
            parsing_headers = False
            continue
        if parsing_headers:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        else:
            body = line if body is None else body + "\n" + line

    parsed = {
        "method": method,
        "endpoint": endpoint,
        "headers": headers,
        "body": body
    }
    return parsed

def dissect_http(pcap_file, limit=10):
    """
    Reads packets from .pcap and extracts API-level insights.
    """
    packets = rdpcap(pcap_file)
    insights = []

    for pkt in packets:
        if IP in pkt and TCP in pkt and Raw in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            payload = pkt[Raw].load

            http_info = parse_http_payload(payload)
            if http_info:
                summary = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": sport,
                    "dst_port": dport,
                    "method": http_info["method"],
                    "endpoint": http_info["endpoint"],
                    "headers": http_info["headers"],
                    "payload": http_info["body"],
                    "likely_encrypted": False
                }
                insights.append(summary)

                if limit and len(insights) >= limit:
                    break

    return insights

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dissector.py <pcap_file> [limit]", file=sys.stderr)
        sys.exit(1)

    pcap_path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 0  # 0 or no arg = use default

    results = dissect_http(pcap_path, limit=limit)
    print(json.dumps(results, indent=2))
