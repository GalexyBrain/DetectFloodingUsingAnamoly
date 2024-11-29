import pyshark

def detect_ping_flood(pcap_file, threshold=100):
    """
    Detect potential ping flooding in a pcap file and identify attacker IPs.
    
    Args:
    - pcap_file: Path to the pcapng file to analyze.
    - threshold: ICMP packet rate per second considered as potential flooding.
    """
    try:
        # Read the pcap file
        capture = pyshark.FileCapture(pcap_file, display_filter="icmp")

        # Dictionary to count packets per source IP per second
        icmp_packet_count = {}

        for packet in capture:
            # Extract the timestamp (in seconds) and source IP
            timestamp = int(float(packet.sniff_timestamp))
            src_ip = packet.ip.src

            # Initialize nested dictionary for the timestamp
            if timestamp not in icmp_packet_count:
                icmp_packet_count[timestamp] = {}

            # Increment packet count for the corresponding source IP and timestamp
            icmp_packet_count[timestamp][src_ip] = (
                icmp_packet_count[timestamp].get(src_ip, 0) + 1
            )

        capture.close()

        # Analyze packet rates
        flooding_detected = False
        print("Analyzing ICMP packet rates...")
        attacker_ips = {}

        for timestamp, sources in icmp_packet_count.items():
            for src_ip, count in sources.items():
                if count > threshold:
                    flooding_detected = True
                    print(f"[ALERT] Potential flooding from {src_ip} at timestamp {timestamp}: {count} ICMP packets (Threshold: {threshold})")
                    # Track attacker IPs and their counts
                    attacker_ips[src_ip] = attacker_ips.get(src_ip, 0) + count

        if flooding_detected:
            print("\nSummary of Potential Attackers:")
            for attacker, total_count in attacker_ips.items():
                print(f"  - {attacker}: {total_count} ICMP packets")
        else:
            print("No flooding detected.")

    except Exception as e:
        print(f"Error processing pcap file: {e}")

# Example usage
pcap_file = "data1.pcapng"  # Replace with the actual file path
threshold = 100  # Define a packet rate threshold
detect_ping_flood(pcap_file, threshold)
