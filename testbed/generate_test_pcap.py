# generate_test_pcap.py
from scapy.all import IP, TCP, Raw, Ether, wrpcap

packets = []

# Simulate POST /login with JSON body
post_login = Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=12345, dport=80)/Raw(
    load=b"POST /login HTTP/1.1\r\nHost: testapisecurity.com\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin\",\"password\":\"123\"}"
)
packets.append(post_login)

# Simulate GET /data request
get_data = Ether()/IP(src="10.0.0.6", dst="10.0.0.10")/TCP(sport=12346, dport=80)/Raw(
    load=b"GET /data HTTP/1.1\r\nHost: testapisecurity.com\r\n\r\n"
)
packets.append(get_data)

# Simulate POST /update with JSON body
post_update = Ether()/IP(src="10.0.0.7", dst="10.0.0.10")/TCP(sport=12347, dport=80)/Raw(
    load=b"POST /update HTTP/1.1\r\nHost: testapisecurity.com\r\nContent-Type: application/json\r\n\r\n{\"value\":42}"
)
packets.append(post_update)

# Simulate a GET /status request
get_status = Ether()/IP(src="10.0.0.8", dst="10.0.0.10")/TCP(sport=12348, dport=80)/Raw(
    load=b"GET /status HTTP/1.1\r\nHost: testapisecurity.com\r\n\r\n"
)
packets.append(get_status)

# Write packets to a .pcap file
wrpcap("test.pcap", packets)

print("Generated simulated_api.pcap with 4 API calls!")
