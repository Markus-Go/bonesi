import random
import struct

NUM_TCP_OPTIONS = 7

class TcpOption:
    def __init__(self, length, options, prob):
        self.length = length
        self.options = options
        self.prob = prob

def init_tcp_options():
    tcp_options = []

    tcp_options.append(TcpOption(20, b"\x03\x03\x0a\x01\x02\x04\x01\x09\x08\x0a\x3f\x3f\x3f\x3f\x00\x00\x00\x00\x00\x00", 0.46 / 3.0))
    tcp_options.append(TcpOption(20, b"\x02\x04\x05\xb4\x01\x03\x03\x00\x01\x01\x08\x0a\x00\x75\x0a\x22\x00\x00\x00\x00", 0.46 / 3.0))
    tcp_options.append(TcpOption(20, b"\x02\x04\x05\x96\x04\x02\x08\x0a\x6d\xb4\x5f\xae\x00\x00\x00\x00\x01\x03\x03\x00", 0.46 / 3.0))
    tcp_options.append(TcpOption(8, b"\x02\x04\x05\xec\x01\x01\x04\x02", 0.38 / 2.0))
    tcp_options.append(TcpOption(8, b"\x02\x04\x05\xb4\x01\x01\x04\x02", 0.38 / 2.0))
    tcp_options.append(TcpOption(12, b"\x02\x04\x05\xb4\x01\x03\x03\x02\x01\x01\x04\x02", 0.05))
    tcp_options.append(TcpOption(24, b"\x02\x04\x05\x7a\x01\x03\x03\x00\x01\x01\x08\x0a\x51\x60\x8e\x68\x00\x00\x00\x00\x04\x02\x00\x00", 0.1))

    return tcp_options

def rand_tcp_options_index(tcp_options):
    tcp_options_prob = random.random()
    for i, option in enumerate(tcp_options):
        tcp_options_prob -= option.prob
        if tcp_options_prob <= 0.0:
            return i
    return len(tcp_options) - 1
