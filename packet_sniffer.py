from scapy.all import sniff
from utils.parser import process_packet

def main():
    print("Starting Packet Sniffer...")
    sniff(prn=process_packet, count=10)

if __name__ == "__main__":
    main()
