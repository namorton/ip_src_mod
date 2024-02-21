import tkinter as tk
from tkinter import filedialog
from tkinter import ttk  # For the progress bar
from scapy.all import *
import ipaddress
import os

DESTINATION_ADDR = "239.255.0.11"
SOURCE_IP_ADDR   = "172.17.28.99"
SOURCE_PORT      = "31000"
WINDOW_SIZE      = "500x300"
PADX             = 15
PBAR_LENGTH      = 500

# Function to change the source IP address for a given destination address
def change_source_ip(pkt, source_port, source_ip, destination_ip):
    pkt_changed = False
    if IP in pkt and pkt[IP].dst == destination_ip:
        if UDP in pkt:
            pkt[UDP].sport = int(source_port)
        pkt[IP].src = source_ip
        del pkt[IP].chksum  # Recalculate the checksum
        pkt_changed = True
    return pkt, pkt_changed

# Function to handle the "Browse" button click for input file selection
def browse_input_file():
    input_file = filedialog.askopenfilename()
    input_entry.delete(0, tk.END)  # Clear the current entry
    input_entry.insert(0, input_file)  # Set the selected file path
    set_default_output_file(input_file)

# Function to set the default output file name based on the input file
def set_default_output_file(input_file):
    base_name = os.path.basename(input_file)
    output_file = 'ip_update_' + base_name
    output_entry.delete(0, tk.END)  # Clear the current entry
    output_entry.insert(0, output_file)  # Set the default output file name

# Function to handle the "Modify" button click
def modify_packets():
    input_file = input_entry.get()
    output_file = output_entry.get()
    source_port = source_port_entry.get()
    source_ip = source_ip_entry.get()
    destination_ip = destination_ip_entry.get()

    # Ensure the source IP is a valid IPv4 address
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        result_label.config(text="Invalid source IP address. Please enter a valid IPv4 address.")
        return

    # Ensure the destination IP is a valid IPv4 address
    try:
        ipaddress.ip_address(destination_ip)
    except ValueError:
        result_label.config(text="Invalid destination IP address. Please enter a valid IPv4 address.")
        return

    packets = rdpcap(input_file)
    total_packets = len(packets)

    # Create a list to store modified packets
    modified_packets = []

    # Create a progress bar
    progress_bar['maximum'] = total_packets

    # Initialize variables to keep track of the previous packet's data
    prev_packet_data = None

    # Process each packet and change the source IP if it matches the destination IP address
    for i, packet in enumerate(packets):
        # Serialize the packet to compare its data
        current_packet_data = bytes(packet)
        
        # Check if the current packet is the same as the previous one
        if current_packet_data != prev_packet_data:
            modified_packet, packet_changed = change_source_ip(packet, source_port, source_ip, destination_ip)
            if packet_changed:
                modified_packets.append(modified_packet)
            prev_packet_data = current_packet_data

        # Update the progress bar
        progress_bar['value'] = i + 1
        window.update_idletasks()

    # Write the modified packets to a new PCAP file
    wrpcap(output_file, modified_packets)
    result_label.config(text=f"Modified packets written to {output_file}")

    # Quit the application 5 seconds after finishing processing
    window.after(5000, window.quit)

# Create the main window
window = tk.Tk()
window.title("IP Source Modifier")
window.geometry(WINDOW_SIZE)

# Create input fields and labels
input_label = tk.Label(window, text="Input PCAP File:")
input_label.pack(anchor='w', padx=PADX)

input_frame = tk.Frame(window)
input_frame.pack(anchor='w', padx=PADX)

input_entry = tk.Entry(input_frame)
input_entry.pack(side='left', expand=True, fill='x')
browse_button = tk.Button(input_frame, text="Browse", command=browse_input_file)
browse_button.pack(side='left')

# Create the "Modify" button
modify_button = tk.Button(input_frame, text="Modify", command=modify_packets)
modify_button.pack(anchor='w', padx=PADX)

output_label = tk.Label(window, text="Output PCAP File:")
output_label.pack(anchor='w', padx=PADX)
output_entry = tk.Entry(window)
output_entry.pack(anchor='w', padx=PADX)

source_port_label = tk.Label(window, text="New Source Port:")
source_port_label.pack(anchor='w', padx=PADX)
source_port_entry = tk.Entry(window)
source_port_entry.insert(0, SOURCE_PORT)
source_port_entry.pack(anchor='w', padx=PADX)

source_ip_label = tk.Label(window, text="New Source IP Address:")
source_ip_label.pack(anchor='w', padx=PADX)
source_ip_entry = tk.Entry(window)
source_ip_entry.insert(0, SOURCE_IP_ADDR)
source_ip_entry.pack(anchor='w', padx=PADX)

destination_ip_label = tk.Label(window, text="Destination IP Address:")
destination_ip_label.pack(anchor='w', padx=PADX)
destination_ip_entry = tk.Entry(window)
destination_ip_entry.insert(0, DESTINATION_ADDR)
destination_ip_entry.pack(anchor='w', padx=PADX)

# Create a label to display the result
result_label = tk.Label(window, text="")
result_label.pack(anchor='w', padx=PADX)

# Create a progress bar
progress_bar = ttk.Progressbar(window, orient="horizontal", length=PBAR_LENGTH, mode="determinate")
progress_bar.pack(anchor='w', padx=PADX)

# Start the Tkinter event loop
window.mainloop()