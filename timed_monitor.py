from scapy.all import sniff
import time
import argparse
import socket
import psutil

ip_list = []
whitelist = []

# Open the whitelist and read its content
with open('whitelist.txt', 'r') as file:
    data = file.read()

# Split the content by commas to convert it into a list
whitelist = data.split(',')

# Print the list
print(whitelist)

def get_domain_name(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)
        print(f"Domain name associated with {ip_address}: {domain_name[0]}")
    except socket.herror as e:
         print(f"Could not resolve IP address {ip_address}: {e}")


# The callback function to process the packets
def process_packet(packet):
    #print(packet.summary())
    #source_ip = packet['IP'].src  # Extract the source IP address
    #print(f"The source IP {source_ip} ")
    destination_ip = packet['IP'].dst  # Extract the source IP address
    #print(f"The destination IP: {destination_ip} ")

    # Adding the IP if it is not already in the list
    if destination_ip not in ip_list:
        ip_list.append(destination_ip)


# The stop filter function
def stop_filter(packet):
    # Stop capturing after the specified end time
    return time.time() >= end_time

# Filter function for outgoing traffic based on specified source IP
def filter_outgoing(packet):
    # Check if the packet has an IP layer and the source IP matches the specified source IP
    return packet.haslayer('IP') and packet['IP'].src == source_ip

# Find the executable responsible for connecting to an IP address
def find_program_for_ip(ip_address):
    # Looping through network connections
    for conn in psutil.net_connections(kind='inet'):
         # Check if both local and remote addresses are available
        if conn.laddr and conn.raddr:
            remote_ip = conn.raddr.ip
            local_ip = conn.laddr.ip
            if remote_ip == ip_address:
                try:
                    pid = conn.pid
                    process = psutil.Process(pid)
                    program_name = process.name()
                    executable_path = process.exe()
                    print(f"Program name: {program_name}")
                    print(f"Executable path: {executable_path}")
                    return program_name
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
    return None

# Parse command line arguments
parser = argparse.ArgumentParser(description="Capture outgoing traffic for a specified source IP.")
parser.add_argument("source_ip", help="The source IP address to filter outgoing traffic.")
parser.add_argument("duration", type=int, help="Duration to capture packets (in seconds).")
args = parser.parse_args()

source_ip = args.source_ip
sniff_duration = args.duration

# Calculate the end time
end_time = time.time() + sniff_duration

# Start sniffing packets
print(f"Capturing packets for {sniff_duration} seconds, filtering for source IP {source_ip}...")
sniff(prn=process_packet, lfilter=filter_outgoing, stop_filter=stop_filter)

print("\n\nPacket capture complete.")
print(sorted(ip_list))
for ip in ip_list:
    if ip not in whitelist:
        print(f"\nexamining IP: {ip}")
        find_program_for_ip(ip)
        get_domain_name(ip)