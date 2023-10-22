"""
file: myping.py
language: python3
author: Yiyang Liu (comeandcode)
"""

import argparse
import socket
import struct
import time
import secrets

"""
This program is to ping an destination ip address to check network connectivity.
"""


def parse_command() -> dict:
    """
    Parse arguments and return a filter
    :return: my_filter for options
    """
    my_filter = {"count": False, "wait": 1, "packetsize": 56, "timeout": False, "dest": False}
    parser = argparse.ArgumentParser(description="parse command")
    parser.add_argument('dest', help="dest ip address")
    parser.add_argument('-c', '--count', type=str, help="number of packets to send")
    parser.add_argument('-i', '--wait', help="wait for wait seconds")
    parser.add_argument('-s', '--packetsize', help="bytes to send")
    parser.add_argument('-t', '--timeout', help="program will end after timeout seconds")
    args = parser.parse_args()
    my_filter["dest"] = args.dest
    if args.count is not None:
        my_filter["count"] = args.count
    if args.wait is not None:
        my_filter["wait"] = args.wait
    if args.packetsize is not None:
        my_filter["packetsize"] = args.packetsize
    if args.timeout is not None:
        my_filter["timeout"] = args.timeout

    return my_filter


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
    icmp_seq = count
    icmp_data = secrets.token_bytes(int(packetsize))

    icmp_header = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    icmp_checksum = cal_checksum(icmp_header + icmp_data)

    # construct ICMP header with the correct checksum
    icmp_header = struct.pack(icmp_header_format, icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    # append data
    icmp_packet = icmp_header + icmp_data
    return icmp_packet


def recv_icmp(my_socket, start_time):
    """
    Receive echo from dest
    :param my_socket: raw socket
    :param start_time: for statistic on time
    """
    my_socket.settimeout(3)
    while True:
        try:
            packet, addr = my_socket.recvfrom(256)

            # calculate the time
            recv_time = time.time()
            duration = float(recv_time - start_time)
            duration = "{:.3f}".format(duration * 1000)

            # calculate the packet size
            packet_size = len(packet[20:])

            # get ttl from the ip header
            ip_part = packet[0: 20]
            ttl = struct.unpack("!B", ip_part[8:9])[0]

            # get info from the icmp header
            icmp_header = packet[20: 28]
            icmp_type, icmp_code, _, _, icmp_seq = struct.unpack("!BBHHH", icmp_header)

            # if it's an echo
            if icmp_type == 0 and icmp_code == 0:
                print("{} bytes from {}: icmp_seq={} ttl={} time={} ms".
                      format(packet_size, addr[0], icmp_seq, ttl, duration))
                return True
            else:
                return False
        except (socket.error, socket.timeout) as e:
            return False


def send_icmp(count, packetsize, wait, timeout, dest):
    """
    Send ICMP packets with limitations
    :param count: number of packets to send
    :param packetsize: size of the data
    :param wait: time interval
    :param timeout: max time to run
    :param dest: destination ip addr
    """
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_id = 0
    if count is False:
        count = 'inf'
    # print("count: {}".format(count))
    if timeout is False:
        timeout = 'inf'
    # print("timeout: {}".format(timeout))
    start_time = time.time()
    end_time = start_time

    # end loop if timeout or meet the maximum count of packets
    while (float(end_time - start_time) < float(timeout)) and (float(icmp_id) < float(count)):
        if icmp_id != 0:
            time.sleep(float(wait))
        every_start_time = time.time()

        # construct packets and send
        icmp_packet = construct_icmp_packet(icmp_id, packetsize)
        try:
            my_socket.sendto(icmp_packet, (dest, 0))
        except socket.error as e:
            print("Sending Error: {}".format(e))

        # receive echos
        result = recv_icmp(my_socket, every_start_time)
        if result is False:
            print("loss packet")

        # update variables
        icmp_id += 1
        end_time = time.time()

    my_socket.close()


def ping(my_filter):
    count = my_filter["count"]
    wait = my_filter["wait"]
    packetsize = my_filter["packetsize"]
    timeout = my_filter["timeout"]
    dest = my_filter["dest"]
    try:
        dest_addr = socket.gethostbyname(dest)
    except socket.error:
        print("Can't resolve host name.")
        return

    print("PING {} ({}): {} data bytes".format(dest, dest_addr, packetsize))
    send_icmp(count, packetsize, wait, timeout, dest_addr)


def main():
    # parse program command
    my_filter: dict = parse_command()

    # start ping addr
    ping(my_filter)

    # program ended
    print("Ping ended. Thanks for using! Bye~")


if __name__ == "__main__":
    main()
