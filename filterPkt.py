import os
from scapy.utils import PcapWriter
from scapy.all import sniff

# Define the network interface and the packet filter
INTERFACE = "eth0"  # Replace with your interface name
FILTER = "tcp and port 80"

# Define the path to the Bash script
BASH_SCRIPT = "./process_packet.sh"

# URI pattern to filter
URI_PATTERN = "http://open5gs-smf/nsmf-pdusession/v1/sm-contexts/"
pktdump = PcapWriter("/tmp/packet.pcap", append=False, sync=True)

def process_packet(packet):
    """
    Process each captured packet by passing it to the Bash script.
    """
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        if packet.haslayer("Raw"):
            try:
                pktdump = PcapWriter("/tmp/packet.pcap", append=False, sync=True)
                pktdump.write(packet)
                # Pass the temp file path to the Bash script
                os.system(f'{BASH_SCRIPT}')

            except Exception as e:
                pass  # Silently ignore errors

# Start sniffing packets
print(f"Starting packet capture on {INTERFACE}...")
sniff(iface=INTERFACE, filter=FILTER, prn=process_packet)
