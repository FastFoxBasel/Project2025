from scapy.all import rdpcap
import pandas as pd
import matplotlib.pyplot as plt
import os

# List to store all file data with labels (activity types)
files_data = []
activities = ['Web-surfing 1', 'Web-surfing 2', 'Audio streaming', 'Video streaming', 'Video conferencing']

def load_and_prepare_data(file_path, activity):
    file_path = os.path.expanduser(file_path)  # Handle ~ for Linux home directories

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return None

    try:
        # Read the pcap file
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None
   
    # Extract relevant information from each packet
    data = []
    for packet in packets:
        if 'IP' in packet:
            data.append({
                'Time': packet.time,
                'Length': len(packet)
            })
   
    # Convert to DataFrame
    data = pd.DataFrame(data)

    if data.empty:
        print(f"No valid packets found in {file_path}")
        return None

    # Ensure 'Length' and 'Time' columns are numeric
    data['Length'] = pd.to_numeric(data['Length'], errors='coerce')
    data['Time'] = pd.to_numeric(data['Time'], errors='coerce')

    # Drop invalid rows
    data.dropna(subset=['Time', 'Length'], inplace=True)

    # Calculate relative time in seconds (starting from 0)
    data['Time'] = data['Time'] - data['Time'].min()

    # Add the activity type to the data
    data['Activity'] = activity
    return data

def analyze_packet_metrics(data, activity):
    
    throughput = data.groupby(data['Time'].astype(int)).sum(numeric_only=True)['Length']
   
    pps = data.groupby(data['Time'].astype(int)).size()

    inter_arrival_times = data['Time'].diff().dropna()

    flow_size = len(data)
    flow_volume = data['Length'].sum()

    return {
        'activity': activity,
        'throughput': throughput,
        'pps': pps,
        'inter_arrival_times': inter_arrival_times,
        'flow_size': flow_size,
        'flow_volume': flow_volume
    }

def plot_comparisons(all_metrics):
    plt.figure(figsize=(15, 18))  # Increase figure height to accommodate more space

    # Plot throughput comparisons
    plt.subplot(3, 2, 1)
    for metrics in all_metrics:
        plt.plot(metrics['throughput'].index, metrics['throughput'].values, label=metrics['activity'])
    plt.title('Throughput Comparison (bytes/s)', pad=20)  # Add padding to the title
    plt.xlabel('Time (seconds)')
    plt.ylabel('Bytes')
    plt.legend()

    # Plot packets per second (PPS) comparisons
    plt.subplot(3, 2, 2)
    for metrics in all_metrics:
        plt.plot(metrics['pps'].index, metrics['pps'].values, label=metrics['activity'])
    plt.title('Packets per Second (PPS) Comparison', pad=20)  # Add padding to the title
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packets')
    plt.legend()

    # Plot inter-arrival times comparison
    plt.subplot(3, 2, 3)
    for metrics in all_metrics:
        plt.plot(metrics['inter_arrival_times'], label=metrics['activity'])
    plt.title('Packet Inter-arrival Times Comparison', pad=20)  # Add padding to the title
    plt.xlabel('Packets')
    plt.ylabel('Inter-arrival Time (seconds)')
    plt.legend()

    # Plot flow size comparison
    plt.subplot(3, 2, 4)
    flow_sizes = [metrics['flow_size'] for metrics in all_metrics]
    activities = [metrics['activity'] for metrics in all_metrics]
    plt.bar(activities, flow_sizes)
    plt.title('Flow Size Comparison (Number of Packets)', pad=20)  # Add padding to the title
    plt.xlabel('Activity')
    plt.ylabel('Packets')

    # Plot flow volume comparison
    plt.subplot(3, 2, 5)
    flow_volumes = [metrics['flow_volume'] for metrics in all_metrics]
    plt.bar(activities, flow_volumes)
    plt.title('Flow Volume Comparison (Total Bytes)', pad=20)  # Add padding to the title
    plt.xlabel('Activity')
    plt.ylabel('Bytes')

    # Adjust layout to prevent overlap
    plt.subplots_adjust(hspace=0.652, wspace=0.41)  # Set custom spacing
    plt.show()

# Load and analyze multiple pcap files
for activity in activities:
    file_path = input(f"Enter the path for {activity} pcap file: ").strip()
    if os.path.exists(os.path.expanduser(file_path)):  # Expand home directory paths
        data = load_and_prepare_data(file_path, activity)
        if data is not None:
            files_data.append(data)
    else:
        print(f"File not found for {activity}, skipping...")

# Process metrics for each activity
all_metrics = []
for data in files_data:
    activity = data['Activity'].iloc[0]  # Get the activity type from data
    metrics = analyze_packet_metrics(data, activity)
    all_metrics.append(metrics)

# Plot comparison graphs for all metrics
plot_comparisons(all_metrics)
