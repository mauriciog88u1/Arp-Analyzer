import pyshark
from mac_vendor_lookup import MacLookup
import networkx as nx
import matplotlib.pyplot as plt

def get_vendor(mac_address):
    try:
        vendor = MacLookup().lookup(mac_address)
        return vendor
    except:
        return "Unknown Vendor"

def get_devices_from_pcap(pcap_filename):
    devices = {}
    cap = pyshark.FileCapture(pcap_filename, display_filter="arp.opcode==1")
    
    for pkt in cap:
        if "ARP" in pkt:
            arp_layer = pkt.arp
            mac_address = arp_layer.src_hw_mac
            if mac_address not in devices:
                vendor = get_vendor(mac_address)
                device_info = {
                    "MAC Address": mac_address,
                    "Vendor": vendor,
                    "IP Address": arp_layer.src_proto_ipv4,
                    "ARP Operation": "ARP Request" if arp_layer.opcode == "1" else "ARP Reply",
                    "Timestamp": pkt.sniff_time
                }
                devices[mac_address] = device_info
    
    return devices

def create_network_topology(pcap_filename):
    cap = pyshark.FileCapture(pcap_filename, display_filter="arp.opcode==1")
    graph = nx.Graph()
    
    for pkt in cap:
        if "ARP" in pkt:
            arp_layer = pkt.arp
            src_mac = arp_layer.src_hw_mac
            dst_mac = arp_layer.dst_hw_mac
            src_vendor = get_vendor(src_mac)
            dst_vendor = get_vendor(dst_mac)
            
            graph.add_node(src_mac, vendor=src_vendor)
            graph.add_node(dst_mac, vendor=dst_vendor)
            graph.add_edge(src_mac, dst_mac)
    
    return graph

if __name__ == "__main__":
    pcap_filename = input("File path for PCAP")
    devices = get_devices_from_pcap(pcap_filename)
    print("Devices found in the pcap:")
    
    for device in devices.values():
        print("\n".join(f"{key}: {value}" for key, value in device.items()))
        print("-" * 20)
    
    network_graph = create_network_topology(pcap_filename)
    
    pos = nx.spring_layout(network_graph)  
    node_labels = nx.get_node_attributes(network_graph, "vendor")
    
    nx.draw(network_graph, pos, with_labels=True, labels=node_labels, node_size=2000, font_size=8)
    plt.title("Network Topology")
    plt.show()
