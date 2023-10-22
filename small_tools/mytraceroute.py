"""
file: mytraceroute.py
language: python3
author: Yiyang Liu (comeandcode)
"""

import argparse
import socket
import struct
import time
import secrets

"""
This program is to traceroute to a destination and print the path.
"""


def parse_command() -> dict:
    """
    Parse arguments and return a filter
    :return: my_filter for options
    """
    my_filter = {"dest": False, "n": False, "q": 3, "S": False}
    parser = argparse.ArgumentParser(description="parse command")
    parser.add_argument('dest', help="dest ip address")
    parser.add_argument('-n', '--n', help="print address numerically", action='store_true')
    parser.add_argument('-q', '--q', help="number of probes per ttl")
    parser.add_argument('-S', '--S', help="number of not answered", action='store_true')
    args = parser.parse_args()

    my_filter["dest"] = args.dest

    if args.q is not None:
        my_filter["q"] = args.q
    if args.n is not None:
        my_filter["n"] = args.n
    if args.S is not None:
        my_filter["S"] = args.S
    return my_filter


def recv_icmp(my_socket, start_time) -> tuple:
    """
    Receive echo from dest
    :param my_socket: raw socket
    :param start_time: for statistic on time
    """
    my_socket.settimeout(2)
    while True:
        try:
            packet, addr = my_socket.recvfrom(256)
            recv_time = time.time()
            duration = float(recv_time - start_time)
            return duration, addr[0]
        except (socket.error, socket.timeout) as e:
            return None, None


def cal_checksum(packet):
    """
    Calculate the checksum of a given ICMP packet
    :param packet: ICMP header with data
    :return: icmp_checksum
    """
    sum = 0
    for i in range(0, len(packet), 2):
        sum += (packet[i] << 8) + packet[i + 1]
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)
    return (~sum) & 0xFFFF


def construct_icmp_packet(count, packetsize):
    """
    Construct an ICMP packet
    :param count: icmp_packet id
    :param packetsize: data to send
    :return: new ICMP packet
    """
    icmp_header_format = '!BBHHH'
    icmp_header_size = struct.calcsize(icmp_header_format)
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = count
    icmp_seq = 1
    icmp_data = secrets.token_bytes(int(packetsize))

    icmp_header = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    icmp_checksum = cal_checksum(icmp_header + icmp_data)

    # construct ICMP header with the correct checksum
    icmp_header = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    # append data
    icmp_packet = icmp_header + icmp_data
    return icmp_packet


def send_icmp(dest, ttl, nqueries, numerically, summary):
    """
    send nqueries icmp packets with a given ttl
    :param dest: dest ip addr
    :param ttl: time to live
    :param nqueries: number of probes
    :param numerically: one print option
    :param summary: one print option
    :return: None
    """
    addr = None
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # set ttl of ip headers
    my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    # compose packets
    packets = []
    timecost = []
    for i in range(int(nqueries)):
        packet = construct_icmp_packet(i, 24)
        packets.append(packet)

    # send and receive packets and count the number of loss
    count_loss = 0
    for packet in packets:
        start_time = time.time()
        try:
            my_socket.sendto(packet, (dest, 0))
        except socket.error as e:
            print("Sending Error: {}".format(e))
        time_cost, one_addr = recv_icmp(my_socket, start_time)
        if time_cost is None:
            timecost.append("*")
            count_loss += 1
        else:
            timecost.append(time_cost)
        if one_addr is not None:
            addr = one_addr

    # print result
    if numerically:
        print("{}  {}".format(ttl, addr), end="")
    else:
        # consider all packets in one hop may be lost
        if addr is not None:
            try:
                host, _, _ = socket.gethostbyaddr(addr)
            except socket.herror:
                host = addr
            print("{}  {} ({})".format(ttl, host, addr), end="")
        else:
            print("{}".format(ttl))
    for one_time in timecost:
        # print * if there is a loss
        if one_time == "*":
            print("   * ", end="")
        else:
            one_time = "{:.3f}".format(one_time * 1000)
            print("   {} ms".format(one_time), end="")
    print()

    # print the number of loss if necessary
    if summary:
        print("   {} probes were not answered for hop {}".format(count_loss, ttl))

    my_socket.close()
    return addr


def traceroute(my_filter):
    """
    start traceroute for 64 times at most
    :param my_filter: options
    :return: None
    """
    dest = my_filter["dest"]
    numerically = my_filter["n"]
    nqueries = my_filter["q"]
    summary_not_answered = my_filter["S"]

    # find the ip address from the host name
    try:
        dest_addr = socket.gethostbyname(dest)
    except socket.error:
        print("Can't resolve host name.")
        return

    print("traceroute to {} ({}), 64 hops max, 52 byte packets".format(dest, dest_addr))
    # increase ttl by 1 each step
    ttl = 1
    while ttl <= 64:
        addr = send_icmp(dest_addr, ttl, nqueries, numerically, summary_not_answered)

        if addr == dest_addr:
            break

        ttl += 1


def main():
    # parse program command
    my_filter: dict = parse_command()

    # start ping addr
    traceroute(my_filter)

    # program ended
    print("Traceroute ended. Thanks for using! Bye~")


if __name__ == "__main__":
    main()
