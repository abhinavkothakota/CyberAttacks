import pandas as pd
from scapy.all import sniff, IP, TCP
from datetime import datetime, timedelta
import os

# CSV file to store captured data
csv_filename = 'network_intrusion_data.csv'

# Initialize CSV file with headers if not already present
if not os.path.exists(csv_filename):
    pd.DataFrame(columns=[
        'attack_neptune', 'attack_normal', 'attack_satan', 'count',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_same_srv_rate', 'dst_host_srv_count', 'flag_S0', 'flag_SF',
        'last_flag', 'logged_in', 'same_srv_rate', 'serror_rate',
        'service_http'
    ]).to_csv(csv_filename, index=False)

# Variables to track the state across multiple packets
packet_counts = {}  # Track the count of connections to each destination
same_src_port_counts = {}
same_srv_counts = {}

def reset_counters():
    global packet_counts, same_src_port_counts, same_srv_counts
    packet_counts = {}
    same_src_port_counts = {}
    same_srv_counts = {}

# Function to update counts and rates
def update_counts(packet):
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport if packet.haslayer(TCP) else None
    service = packet[TCP].dport if packet.haslayer(TCP) else None

    # Update packet count for destination IP
    if dst_ip not in packet_counts:
        packet_counts[dst_ip] = 1
    else:
        packet_counts[dst_ip] += 1

    # Track connections to the same source port
    if src_port:
        if src_port not in same_src_port_counts:
            same_src_port_counts[src_port] = 1
        else:
            same_src_port_counts[src_port] += 1

    # Track connections to the same service
    if service:
        if service not in same_srv_counts:
            same_srv_counts[service] = 1
        else:
            same_srv_counts[service] += 1

def calculate_rates():
    total_connections = sum(packet_counts.values())
    diff_srv_rate = len(packet_counts) / total_connections if total_connections > 0 else 0
    same_src_port_rate = max(same_src_port_counts.values()) / total_connections if same_src_port_counts else 0
    same_srv_rate = max(same_srv_counts.values()) / total_connections if same_srv_counts else 0
    srv_count = len(same_srv_counts)

    return diff_srv_rate, same_src_port_rate, same_srv_rate, srv_count

def extract_packet_data(packet):
    try:
        # Placeholder attack flags (0 or 1) based on analysis or simulation
        attack_neptune = 0
        attack_normal = 1
        attack_satan = 0

        # Update counters and rates
        update_counts(packet)
        dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_same_srv_rate, dst_host_srv_count = calculate_rates()

        # Check flags
        flag_S0 = 1 if packet.haslayer(TCP) and packet[TCP].flags == 0 else 0
        flag_SF = 1 if packet.haslayer(TCP) and packet[TCP].flags == 0x02 else 0
        last_flag = packet[TCP].flags if packet.haslayer(TCP) else None

        # Placeholder for logged_in, which we cannot directly detect
        logged_in = 0

        # Calculate same_srv_rate and serror_rate (assuming some error flags)
        same_srv_rate = dst_host_same_srv_rate
        serror_rate = 0.0  # Placeholder

        # Check if service is HTTP based on port
        service_http = 1 if packet.haslayer(TCP) and packet[TCP].dport in [80, 443] else 0

        # Count total packets to the destination within 2 seconds for the `count` feature
        count = packet_counts[packet[IP].dst]

        # Construct data dictionary
        packet_data = {
            'attack_neptune': attack_neptune,
            'attack_normal': attack_normal,
            'attack_satan': attack_satan,
            'count': count,
            'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
            'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
            'dst_host_same_srv_rate': dst_host_same_srv_rate,
            'dst_host_srv_count': dst_host_srv_count,
            'flag_S0': flag_S0,
            'flag_SF': flag_SF,
            'last_flag': last_flag,
            'logged_in': logged_in,
            'same_srv_rate': same_srv_rate,
            'serror_rate': serror_rate,
            'service_http': service_http
        }

        # Append data to CSV
        save_to_csv(packet_data)

    except Exception as e:
        print(f"An error occurred while processing packet: {e}")

def save_to_csv(data):
    # Append packet data to CSV file
    df = pd.DataFrame([data])
    df.to_csv(csv_filename, mode='a', header=False, index=False)
    print(f"Data saved to {csv_filename}: {data}")

def start_packet_capture():
    print("Starting packet capture...")
    sniff(prn=extract_packet_data, store=False)

if __name__ == "__main__":
    # Reset counters every 2 seconds to keep data updated for real-time analysis
    reset_interval = 2
    last_reset_time = datetime.now()

    while True:
        # Capture packets
        start_packet_capture()
        
        # Reset counters periodically
        if (datetime.now() - last_reset_time) > timedelta(seconds=reset_interval):
            reset_counters()
            last_reset_time = datetime.now()
