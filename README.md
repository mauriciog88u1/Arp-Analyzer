# Network Analyzer

This Python script is a network analyzer that processes packet capture (PCAP) files to extract information about devices and visualize network topology. It utilizes the `pyshark`, `mac_vendor_lookup`, `networkx`, and `matplotlib` libraries.

## Device Information

### Getting Vendor Information
- The script uses the `MacLookup` library to look up the vendor information associated with MAC addresses found in the PCAP file.

### Extracting Devices
- The `get_devices_from_pcap` function reads the PCAP file and identifies devices by analyzing ARP (Address Resolution Protocol) packets with an ARP request opcode.
- For each device found, it extracts the following information:
    - MAC Address
    - Vendor (resolved from MAC address)
    - IP Address (from ARP packet)
    - ARP Operation (ARP Request or ARP Reply)
    - Timestamp of the packet

### Creating a Device List
- The script creates a list of devices found in the PCAP file and prints their details to the console.

## Network Topology Visualization

### Creating Network Topology
- The `create_network_topology` function builds a network topology graph based on ARP packets in the PCAP file.
- It identifies devices by their MAC addresses and associates vendors with each device.
- Nodes represent devices, and edges represent ARP communication between devices.

### Network Visualization
- The script uses `networkx` and `matplotlib` to visualize the network topology.
- Nodes in the graph are labeled with vendor information, making it easy to identify device types.
- The graph is displayed using a spring layout for clarity.

## Usage
- When you run the script, it prompts you to provide the file path for the PCAP file you want to analyze.
- After processing, it prints the devices found in the PCAP, including their MAC addresses, vendors, IP addresses, ARP operations, and timestamps.
- Additionally, it displays a network topology graph that shows how devices are connected in the network.

Please make sure to have the necessary libraries installed and provide the correct PCAP file path to analyze your network data.

