"""
file: pktanalyzer.py
language: python3
author: Yiyang Liu (comeandcode)
"""
import argparse
import socket
import struct
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

"""
This program is to analyze packets and print out the results.
"""


# parse program command
def parse_command() -> dict:
    my_filter = {"file": False, "max_packets": False, "host": False, "port": False, "ip": False, "tcp": False,
                 "udp": False, "icmp": False, "net": False}
    parser = argparse.ArgumentParser(description="parse command")
    parser.add_argument('-r', '--filename', type=str, help="command to read file")
    parser.add_argument('-c', '--max_packets', help="number of files to analyze")
    parser.add_argument('-host', '--host_address', help="target host name")
    parser.add_argument('-port', '--port_number', help="target port name")
    parser.add_argument('-ip', '--ip', action='store_true')
    parser.add_argument('-tcp', '--tcp', action='store_true')
    parser.add_argument('-udp', '--udp', action='store_true')
    parser.add_argument('-icmp', '--icmp', action='store_true')
    parser.add_argument('-net', '--net', help="target net name")
    args = parser.parse_args()

    # store values from arguments to build up the filter dict
    my_filter["file"] = args.filename
    if args.max_packets is not None:
        my_filter["max_packets"] = args.max_packets
    if args.host_address is not None:
        my_filter["host"] = args.host_address

    if args.port_number is not None:
        my_filter["port"] = args.port_number
    if args.ip is not None:
        my_filter["ip"] = args.ip

    if args.tcp is not None:
        my_filter["tcp"] = args.tcp
    if args.udp is not None:
        my_filter["udp"] = args.udp

    if args.icmp is not None:
        my_filter["icmp"] = args.icmp
    if args.net is not None:
        my_filter["net"] = args.net
    return my_filter


def print_eth_ip(is_ipv4: bool, values: dict):
    # print Ethernet header
    print("\n-----Ether Header----")
    print("Packet Size: {}".format(values.get("packet_size")))
    print("Destination: {}".format(values.get("dest_mac")))
    print("Source: {}".format(values.get("src_mac")))
    print("EtherType: {}".format(hex(values.get("ether_type"))))

    # print IPv4 header
    print("\n-----IP Header----")
    print("Version: {}".format(values.get("version")))
    print("Header length: {} bytes".format(values.get("ihl") * 4))
    print("Type of service: {}".format(hex(values.get("tos"))))
    print("Total length: {} bytes".format(values.get("ip_total_length")))
    print("Identification: {}".format(values.get("ip_id")))
    print("Flags: {}".format(values.get("flags")))
    print("Fragment offset: {} bytes".format(values.get("frag_offset")))
    print("Time to live: {} seconds/hops".format(values.get("ttl")))
    print("Protocol: {}".format(values.get("protocol")))
    print("Header checksum: {}".format(hex(values.get("ip_checksum"))))
    print("Source Address: {}, ({})".format(values.get("src_ip"), values.get("src_name")))
    print("Destination Address: {}, ({})".format(values.get("dest_ip"), values.get("dest_name")))


def analyze_tcp(raw_packet: bytes, size: int, eth_ip_values: dict, port):
    tcp_header_format = '!HHIIBBHHH'
    tcp_header_size = struct.calcsize(tcp_header_format)

    # extract TCP header
    tcp_header = struct.unpack(
        tcp_header_format,
        raw_packet[size:size + tcp_header_size]
    )

    src_port, dest_port, seq_num, ack_num, data_offset_flags, flags, window_size, tcp_checksum, urgent_ptr = tcp_header
    data_offset = (data_offset_flags >> 4) * 4

    # print filter-satisfied data
    if (port is False) or (str(src_port) == port or str(dest_port) == port):
        print_eth_ip(True, eth_ip_values)
        print("\n-----TCP Header----")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dest_port}")
        print(f"Sequence Number: {seq_num}")
        print(f"Acknowledgment Number: {ack_num}")
        print(f"Data Offset: {data_offset} bytes")
        print(f"Flags: {hex(flags)}")
        print(f"Window: {window_size}")
        print(f"Checksum: {hex(tcp_checksum)}")
        print(f"Urgent pointer: {urgent_ptr}")


def analyze_udp(raw_packet: bytes, size: int, eth_ip_values: dict, port):
    udp_header_format = '!HHHH'
    udp_header_size = struct.calcsize(udp_header_format)

    # extract UDP header
    udp_header = struct.unpack(
        udp_header_format,
        raw_packet[size:size + udp_header_size]
    )

    src_port, dest_port, udp_length, udp_checksum = udp_header

    # print filter-satisfied data
    if (port is False) or (str(src_port) == port) or (str(dest_port) == port):
        print_eth_ip(True, eth_ip_values)
        print("\n-----UDP Header----")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dest_port}")
        print(f"UDP Length: {udp_length}")
        print(f"UDP Checksum: {hex(udp_checksum)}")


def analyze_icmp(raw_packet: bytes, size: int, eth_ip_values: dict, port):
    icmp_header_format = '!BBH'
    icmp_header_size = struct.calcsize(icmp_header_format)

    # extract ICMP header
    icmp_header = struct.unpack(
        icmp_header_format,
        raw_packet[size:size + icmp_header_size]
    )

    icmp_type, icmp_code, icmp_checksum = icmp_header

    # print filter-satisfied data
    if port is False:
        print_eth_ip(True, eth_ip_values)
        print("\n-----ICMP Header----")
        print(f"ICMP Type: {icmp_type}")
        print(f"ICMP Code: {icmp_code}")
        print(f"ICMP Checksum: {hex(icmp_checksum)}")


# # check if either src or dest is in a given subnet
def check_net(net, src, dest) -> bool:
    count = 0
    index = 0
    for i, char in enumerate(net):
        if char == '.':
            count += 1
            if count == 3:
                index = i + 1
    return (net[:index] == src[:index]) or (net[:index] == src[:index])


# analyze IP packets
def analyze_ip(is_ipv4: bool, raw_packet: bytes, eth_header_size: int, my_filter: dict, eth_values: dict):
    # define IPv4 header format
    ipv4_header_format = '!BBHHHBBH4s4s'
    ipv4_header_size = struct.calcsize(ipv4_header_format)

    # extract IPv4 header
    ip_header = struct.unpack(ipv4_header_format, raw_packet[eth_header_size:eth_header_size + ipv4_header_size])

    version = (ip_header[0] >> 4) & 0xF
    ihl = ip_header[0] & 0xF
    tos = ip_header[1]
    total_length = ip_header[2]
    identification = ip_header[3]
    flags = (ip_header[4] >> 13) & 0x7
    fragment_offset = ip_header[4] & 0x1FFF
    ttl = ip_header[5]
    protocol = ip_header[6]
    ip_checksum = ip_header[7]
    dest_ip = '.'.join(map(str, ip_header[9]))
    src_ip = '.'.join(map(str, ip_header[8]))

    # analyze type of protocol
    if protocol == 6:
        protocol_name = " (TCP)"
    elif protocol == 17:
        protocol_name = " (UDP)"
    elif protocol == 1:
        protocol_name = " (ICMP)"
    else:
        protocol_name = ""

    # try to get the hostnames of ip addresses
    try:
        dest_name, _, _ = socket.gethostbyaddr(dest_ip)
    except socket.herror as e:
        dest_name = "private/unknown"

    try:
        src_name, _, _ = socket.gethostbyaddr(src_ip)
    except socket.herror as e:
        src_name = "private/unknown"

    # store filter-satisfied data for printing
    if ((my_filter["net"] is False) or check_net(my_filter["net"], src_ip, dest_ip)) and (
            (my_filter["host"] is False) or (my_filter["host"] == src_ip) or (my_filter["host"] == src_ip)):
        eth_ip_values = eth_values
        eth_ip_values["version"] = version
        eth_ip_values["ihl"] = ihl
        eth_ip_values["tos"] = tos
        eth_ip_values["ip_total_length"] = total_length
        eth_ip_values["ip_id"] = identification
        eth_ip_values["flags"] = flags
        eth_ip_values["frag_offset"] = fragment_offset
        eth_ip_values["ttl"] = ttl
        eth_ip_values["protocol"] = str(protocol) + protocol_name
        eth_ip_values["ip_checksum"] = ip_checksum
        eth_ip_values["dest_ip"] = dest_ip
        eth_ip_values["dest_name"] = dest_name
        eth_ip_values["src_name"] = src_name
        eth_ip_values["src_ip"] = src_ip

        # analyze Transmission Layer
        if protocol == 6 and ((my_filter["udp"] is False and my_filter["icmp"] is False) or my_filter["tcp"] is True):
            analyze_tcp(raw_packet, eth_header_size + ipv4_header_size, eth_ip_values, my_filter["port"])
        elif protocol == 17 and (
                (my_filter["tcp"] is False and my_filter["icmp"] is False) or my_filter["udp"] is True):
            analyze_udp(raw_packet, eth_header_size + ipv4_header_size, eth_ip_values, my_filter["port"])
        elif protocol == 1 and ((my_filter["tcp"] is False and my_filter["udp"] is False) or my_filter["icmp"] is True):
            analyze_icmp(raw_packet, eth_header_size + ipv4_header_size, eth_ip_values, my_filter["port"])


# analyze Ethernet packets
def analyze_p_helper(p: bytes, my_filter: dict):
    raw_packet = p
    packet_size = len(raw_packet)
    # define Ethernet frame format
    eth_header_format = '!6s6sH'
    eth_header_size = struct.calcsize(eth_header_format)

    # extract Ethernet header fields
    dest_mac, src_mac, ether_type = struct.unpack(eth_header_format, raw_packet[:eth_header_size])

    # convert the format
    dest_mac = ':'.join(f'{byte:02X}' for byte in dest_mac)
    src_mac = ':'.join(f'{byte:02X}' for byte in src_mac)

    # store data for printing
    eth_values = {"packet_size": packet_size, "dest_mac": dest_mac, "src_mac": src_mac, "ether_type": ether_type}

    # check ipv4
    if ether_type == 0x0800:
        analyze_ip(True, raw_packet, eth_header_size, my_filter, eth_values)

    # check if the Ethernet header should be printed or not
    elif (my_filter["tcp"] is False) and (my_filter["udp"] is False) and (my_filter["icmp"] is False) and (
            my_filter["host"] is False) and (my_filter["net"] is False) and (my_filter["port"] is False) and (
            my_filter["ip"] is False):
        # print Ethernet header
        print("\n-----Ether Header (not IPv4 type)----")
        print(f"Packet Size: {packet_size}")
        print(f"Destination: {dest_mac}")
        print(f"Source: {src_mac}")
        print(f"EtherType: {hex(ether_type)}")


# iterate every raw packet for further analysis
def analyze_packet(raw_packets: list, my_filter: dict):
    for p in raw_packets:
        analyze_p_helper(p, my_filter)


# read packets from the target file
def read_packets(actions: dict) -> list:
    file: str = actions["file"]
    max_number = int(actions["max_packets"])

    # extract data from the pcap file
    raw_packets = []
    all_packets = rdpcap(file)

    if max_number != 0:
        for p in all_packets:
            if max_number != 0:
                raw_packets.append(bytes(p))
                max_number -= 1
    else:
        for p in all_packets:
            raw_packets.append(bytes(p))

    return raw_packets


def main():
    # parse program command
    my_filter: dict = parse_command()

    # read packets from a pcap file
    raw_packets = read_packets(my_filter)

    # analyze raw packets
    analyze_packet(raw_packets, my_filter)


if __name__ == "__main__":
    main()
