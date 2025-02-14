# -*- coding: utf-8 -*-
"""
Created on Tue Feb 14 08:27:25 2025

@author: IAN CARTER KULANI

"""

import scapy.all as scapy
import matplotlib.pyplot as plt
from collections import defaultdict
import time

# Threshold for detecting possible UDP Flooding (packets per time window)
THRESHOLD = 100
TIME_WINDOW = 10  # Time window in seconds to track packet counts

# Dictionary to store the count of packets for each IP
packet_count = defaultdict(int)

# Function to handle packet capture and count UDP packets
def packet_handler(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP):
        source_ip = packet[scapy.IP].src
        packet_count[source_ip] += 1

# Function to capture UDP packets for a specific IP
def capture_udp_packets(ip_to_monitor):
    print(f"Monitoring UDP traffic for IP: {ip_to_monitor}")
    print("Press Ctrl+C to stop capturing.")
    
    # Time tracking to monitor packet counts in a specific window
    start_time = time.time()
    time_window_data = []

    while True:
        try:
            # Capture packets and apply packet_handler
            scapy.sniff(prn=packet_handler, filter="udp", store=0, timeout=1)
            
            # Track the number of UDP packets from the monitored IP
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME_WINDOW:
                # Collect data at the end of the time window
                time_window_data.append((elapsed_time, packet_count[ip_to_monitor]))
                
                # Reset the counters for the next time window
                packet_count.clear()
                start_time = time.time()

            # Stop after some time (optional), you can modify this logic
            if elapsed_time > 60:  # Run for 1 minute
                break

        except KeyboardInterrupt:
            break

    return time_window_data

# Function to plot data in a curve graph
def plot_graph(time_window_data):
    times = [data[0] for data in time_window_data]
    counts = [data[1] for data in time_window_data]
    
    plt.plot(times, counts, marker='o', linestyle='-', color='b', label="UDP Packets")
    plt.title('UDP Flooding Detection Over Time')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packet Count')
    plt.grid(True)
    plt.legend()
    plt.show()

# Main function to run the program
def main():
    # Prompt user for IP address to monitor
    ip_to_monitor = input("Enter the IP address to monitor: ")

    # Capture UDP packets and monitor traffic for the given IP address
    time_window_data = capture_udp_packets(ip_to_monitor)

    # After capturing, plot the results in a curve graph
    plot_graph(time_window_data)

    # Check if the count exceeds the threshold and print the result
    if time_window_data[-1][1] > THRESHOLD:
        print(f"Possible UDP flooding attack detected for IP {ip_to_monitor}.")
    else:
        print(f"No UDP flooding detected for IP {ip_to_monitor}.")

if __name__ == "__main__":
    main()
