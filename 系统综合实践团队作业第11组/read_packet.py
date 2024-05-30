import scapy.all as scapy
import json
import os

def analyze_pcap(file_name):
    while True:
        try:

            packets = scapy.rdpcap("./pcaps/"+file_name+".pcap")
            break
        except:
            print("file is empty")
            return;
    udp_count = 0
    tcp_count = 0
    ecn_full=0
    source_ips = set()
    destination_ips = set()

    packets = scapy.rdpcap("./pcaps/" + file_name + ".pcap")
    for packet in packets:
        if 'IP' in packet:
            source_ips.add(packet[scapy.IP].src)
            destination_ips.add(packet[scapy.IP].dst)

        if 'UDP' in packet:
            udp_count += 1
        elif 'TCP' in packet:
            tcp_count += 1
        if "tos" in packet:
                if "3" in packet:
                    ecn_full=1
                else :
                    ecn_full=0
    result = {
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "source_ips": list(source_ips),
        "destination_ips": list(destination_ips),
        "ecn": ecn_full
    }

    with open("./record_file/" + file_name + ".json", "w") as f:
        json.dump(result, f, indent=4)

def read_and_save(file_name):
    if os.path.exists("./record_file/"+file_name+".json"):
        with open("./record_file/"+file_name+".json", "r") as f:
            data = json.load(f)
            udp_count = data.get("udp_count", 0)
            tcp_count = data.get("tcp_count", 0)
            source_ips = data.get("source_ips", [])
            destination_ips = data.get("destination_ips", [])
            print("UDP Count:", udp_count)
            print("TCP Count:", tcp_count)
            print("Source IPs:", source_ips)
            print("Destination IPs:", destination_ips)

if __name__ == "__main__":
  # 请替换为你的pcap文件名（不含扩展名）
    analyze_pcap(file_name)
    read_and_save(file_name)
