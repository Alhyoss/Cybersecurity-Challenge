1. Open the pcap file with WireShark
2. filter the HTTP protocol
3. You will have about 30 HTTP requests, some for the address "/block/...", other for "/address/..."
4. In the json responses of the "/address/..." requests, you have a field "return_value" which contains a base64 string
5. Decode the base64 string of the last HTTP to get the flag
