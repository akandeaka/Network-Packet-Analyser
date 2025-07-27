import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import os
import stat
import sys

# WARNING: Use only on networks you own or have explicit permission to monitor.
# Unauthorized packet sniffing is illegal and unethical.

LOG_FILE = "packet_log.txt"
SNIFFING = False

def get_protocol_name(packet):
    """Determine the protocol name from the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    return "Other"

def analyze_packet(packet, protocol_filter, text_area, log_file):
    """Analyze and display/log packet details."""
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = get_protocol_name(packet)
            if protocol_filter != "All" and protocol != protocol_filter:
                return
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')[:50] if packet.haslayer(scapy.Raw) else "No payload"
            packet_info = (
                f"[{timestamp}]\n"
                f"Source IP: {src_ip}\n"
                f"Destination IP: {dst_ip}\n"
                f"Protocol: {protocol}\n"
                f"Payload: {payload}\n"
                f"{'-' * 50}\n"
            )
            text_area.insert(tk.END, packet_info)
            text_area.see(tk.END)
            with open(log_file, "a") as f:
                f.write(packet_info)
    except Exception as e:
        error_msg = f"[{timestamp}] Error analyzing packet: {str(e)}\n"
        text_area.insert(tk.END, error_msg)
        text_area.see(tk.END)
        with open(log_file, "a") as f:
            f.write(error_msg)

def start_sniffing(interface, protocol_filter, text_area, log_file):
    """Start packet sniffing in a separate thread."""
    global SNIFFING
    SNIFFING = True
    def sniff_packets():
        try:
            scapy.sniff(
                iface=interface,
                prn=lambda p: analyze_packet(p, protocol_filter.get(), text_area, log_file),
                store=False,
                filter=protocol_filter.get().lower() if protocol_filter.get() != "All" else ""
            )
        except Exception as e:
            if SNIFFING:
                text_area.insert(tk.END, f"Error sniffing: {str(e)}\n")
                text_area.see(tk.END)
                with open(log_file, "a") as f:
                    f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error sniffing: {str(e)}\n")
    threading.Thread(target=sniff_packets, daemon=True).start()
    text_area.insert(tk.END, f"Started sniffing on {interface} with filter: {protocol_filter.get()}\n")
    text_area.see(tk.END)

def stop_sniffing(text_area, log_file):
    """Stop packet sniffing."""
    global SNIFFING
    SNIFFING = False
    text_area.insert(tk.END, "Stopped sniffing.\n")
    text_area.see(tk.END)
    with open(log_file, "a") as f:
        f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Stopped sniffing.\n")

def setup_log_file():
    """Set up the log file with secure permissions."""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    with open(LOG_FILE, "a") as f:
        f.write("Packet Sniffer Log - For educational use only.\n")
    try:
        os.chmod(LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # Skip chmod on Windows

def create_gui():
    """Create the GUI for the packet sniffer."""
    root = tk.Tk()
    root.title("Packet Sniffer - Educational Tool")
    root.geometry("600x400")
    
    # Interface selection
    tk.Label(root, text="Select Network Interface (from list below):").pack(pady=5)
    interface_var = tk.StringVar()
    try:
        interfaces = scapy.get_if_list()
        interface_dropdown = ttk.Combobox(root, textvariable=interface_var, values=interfaces, state="readonly")
        interface_dropdown.pack(pady=5)
        if interfaces:
            interface_var.set(interfaces[0])
    except Exception as e:
        interface_dropdown = tk.Entry(root)
        interface_dropdown.pack(pady=5)
        interface_dropdown.insert(0, "Error: Run as Administrator")
    
    # Protocol filter dropdown
    tk.Label(root, text="Protocol Filter:").pack(pady=5)
    protocol_var = tk.StringVar(value="All")
    protocol_dropdown = ttk.Combobox(root, textvariable=protocol_var, values=["All", "TCP", "UDP"], state="readonly")
    protocol_dropdown.pack(pady=5)
    
    # Text area for packet display
    text_area = scrolledtext.ScrolledText(root, height=15, width=70, wrap=tk.WORD)
    text_area.pack(pady=10)
    text_area.insert(tk.END, "Packet Sniffer - For educational use only.\nEnsure you have permission to monitor this network.\n")
    try:
        interfaces = scapy.get_if_list()
        text_area.insert(tk.END, "Available interfaces:\n")
        for iface in interfaces:
            text_area.insert(tk.END, f"{iface}\n")
        text_area.insert(tk.END, "Run 'ipconfig' to match NPF names to Wi-Fi/Ethernet.\n")
    except Exception as e:
        text_area.insert(tk.END, f"Error listing interfaces: {str(e)}\n")
    
    # Buttons
    def start_button_action():
        interface = interface_var.get()
        try:
            interfaces = scapy.get_if_list()
            if interface not in interfaces:
                text_area.insert(tk.END, f"Invalid interface: {interface}. Available: {interfaces}\n")
                return
            setup_log_file()
            start_sniffing(interface, protocol_var, text_area, LOG_FILE)
        except Exception as e:
            text_area.insert(tk.END, f"Error starting sniffer: {str(e)}\n")
    
    tk.Button(root, text="Start Sniffing", command=start_button_action).pack(side=tk.LEFT, padx=20)
    tk.Button(root, text="Stop Sniffing", command=lambda: stop_sniffing(text_area, LOG_FILE)).pack(side=tk.RIGHT, padx=20)
    
    # Prevent GUI from closing until sniffing is stopped
    def on_closing():
        stop_sniffing(text_area, LOG_FILE)
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

def main():
    """Main function to validate and start the GUI."""
    try:
        scapy.get_if_list()
    except Exception as e:
        print(f"Error initializing scapy: {str(e)}")
        sys.exit(1)
    print("Launching Packet Sniffer GUI - For educational use only.")
    create_gui()

if __name__ == "__main__":
    main()