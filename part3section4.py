from scapy.all import rdpcap
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import defaultdict

# Load and extract packet data
def load_pcap(file_path):
    packets = rdpcap(file_path)
    data = []
    for packet in packets:
        if 'IP' in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            src_port = packet.sport if 'TCP' in packet or 'UDP' in packet else None
            dst_port = packet.dport if 'TCP' in packet or 'UDP' in packet else None
            flow_id = hash((src_ip, dst_ip, src_port, dst_port))  # Simulated hashed 4-tuple
            data.append({
                'Time': packet.time,
                'Size': len(packet),
                'Flow_ID': flow_id
            })
    return pd.DataFrame(data)

# Analyze unique flows per app
def analyze_flows(pcap_data, app_name):
    unique_flows = pcap_data['Flow_ID'].nunique()
    total_packets = len(pcap_data)
    total_bytes = pcap_data['Size'].sum()
    return {'App': app_name, 'Unique_Flows': unique_flows, 'Total_Packets': total_packets, 'Total_Bytes': total_bytes}

# Plot packet size distributions
def plot_packet_sizes(pcap_data, app_name):
    sns.histplot(pcap_data['Size'], bins=50, kde=True, label=app_name)
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.title('Packet Size Distribution')
    plt.legend()

# Plot inter-arrival time distributions
def plot_inter_arrival_times(pcap_data, app_name):
    inter_arrival_times = np.diff(pcap_data['Time'].sort_values().values)
    sns.histplot(inter_arrival_times, bins=50, kde=True, label=app_name)
    plt.xlabel('Inter-arrival Time (seconds)')
    plt.ylabel('Frequency')
    plt.title('Packet Inter-arrival Time Distribution')
    plt.legend()

# Compare multiple PCAPs
def compare_apps(pcap_files):
    results = []
    plt.figure(figsize=(12, 5))
    for idx, (file_path, app_name) in enumerate(pcap_files.items()):
        print(f"Processing {app_name}...")
        pcap_data = load_pcap(file_path)
        results.append(analyze_flows(pcap_data, app_name))
        plt.subplot(1, 2, 1)
        plot_packet_sizes(pcap_data, app_name)
        plt.subplot(1, 2, 2)
        plot_inter_arrival_times(pcap_data, app_name)
    plt.show()
    return pd.DataFrame(results)

# User Input for PCAP Files
pcap_files = {}
for app in ['Web-surfing 1', 'Web-surfing 2', 'Audio Streaming', 'Video Streaming', 'Video Conferencing']:
    path = input(f"Enter the pcap file path for {app}: ")
    pcap_files[path] = app

# Run Analysis
results_df = compare_apps(pcap_files)
print(results_df)

