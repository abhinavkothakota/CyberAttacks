import pandas as pd
from scapy.all import sniff, IP, TCP
from datetime import datetime

# List to store packet data
packet_data_list = []

# Define CSV filename
csv_filename = 'network_packets.csv'

def extract_packet_data(packet):
    try:
        packet_data = {
            "timestamp": datetime.now(),
            "attack_neptune": 0,   # Placeholder; Set manually based on analysis
            "attack_normal": 1,    # Placeholder; Set manually based on analysis
            "attack_satan": 0,     # Placeholder; Set manually based on analysis
            "count": 1,            # Requires stateful tracking over time
            "dst_host_diff_srv_rate": 0.0,  # Placeholder
            "dst_host_same_src_port_rate": 0.0,  # Placeholder
            "dst_host_same_srv_rate": 0.0,  # Placeholder
            "dst_host_srv_count": 0,       # Placeholder
            "flag_S0": 1 if packet.haslayer(TCP) and packet[TCP].flags == 0 else 0,
            "flag_SF": 1 if packet.haslayer(TCP) and packet[TCP].flags == 0x02 else 0,
            "last_flag": packet[TCP].flags if packet.haslayer(TCP) else None,
            "logged_in": 0,  # Placeholder
            "same_srv_rate": 0.0,  # Placeholder
            "serror_rate": 0.0,  # Placeholder
            "service_http": 1 if packet.haslayer(TCP) and packet[TCP].dport in [80, 443] else 0,
            "src_ip": packet[IP].src if packet.haslayer(IP) else None,
            "dst_ip": packet[IP].dst if packet.haslayer(IP) else None,
            "protocol": packet[IP].proto if packet.haslayer(IP) else None,
            "src_port": packet.sport if packet.haslayer(TCP) or packet.haslayer('UDP') else None,
            "dst_port": packet.dport if packet.haslayer(TCP) or packet.haslayer('UDP') else None,
            "length": len(packet)
        }
        packet_data_list.append(packet_data)

        # Save to CSV every 100 packets
        if len(packet_data_list) >= 100:
            save_to_csv(packet_data_list)
            packet_data_list.clear()
    except Exception as e:
        print(f"An error occurred while processing packet: {e}")

def save_to_csv(data):
    df = pd.DataFrame(data)
    df.to_csv(csv_filename, mode='a', index=False, header=not pd.io.common.file_exists(csv_filename))
    print(f"{len(data)} packets saved to {csv_filename}")

def start_packet_capture():
    print("Starting packet capture...")
    sniff(prn=extract_packet_data, store=False)

if __name__ == "__main__":
    start_packet_capture()
