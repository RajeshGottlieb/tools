#!/usr/bin/python3
import argparse
import subprocess
import re
import time

'''
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 5000
        inet 192.168.122.6  netmask 255.255.255.0  broadcast 192.168.122.255
        inet6 fe80::5054:ff:fe30:80cb  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:30:80:cb  txqueuelen 1000  (Ethernet)
        RX packets 3088379  bytes 313407923 (298.8 MiB)
        RX errors 0  dropped 1132998  overruns 0  frame 0
        TX packets 349  bytes 17206 (16.8 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
'''

def rx_packets(interface):
    output = subprocess.check_output(f'ifconfig {interface}', encoding='utf-8', shell=True)
    for line in output.split('\n'):
        match = re.search(r'RX packets ([0-9]+)', line)
        if match:
            count = int(match.group(1))
            return count
    return 0;

class Counts:
    def __init__(self):
        self.rx_packets = 0
        self.tx_packets = 0
    def __str__(self):
        return f'rx_packets={self.rx_packets} tx_packets={self.tx_packets}'

def interface_counts(interface):

    counts = Counts()

    output = subprocess.check_output(f'ifconfig {interface}', encoding='utf-8', shell=True)

    for line in output.split('\n'):
        match = re.search(r'RX packets ([0-9]+)', line)
        if match:
            counts.rx_packets = int(match.group(1))

    for line in output.split('\n'):
        match = re.search(r'TX packets ([0-9]+)', line)
        if match:
            counts.tx_packets = int(match.group(1))

    return counts

def main(args):
    print(f'--interface={args.interface} --seconds={args.seconds}')
    start_counts = interface_counts(args.interface)
    print(f'RX packets {start_counts.rx_packets}')
    print(f'TX packets {start_counts.tx_packets}')

    print(f'sleeping for {args.seconds} seconds')
    time.sleep(args.seconds)
    
    end_counts = interface_counts(args.interface)
    print(f'RX packets {end_counts.rx_packets}')
    print(f'TX packets {end_counts.tx_packets}')

    rx_pps = (end_counts.rx_packets - start_counts.rx_packets) / args.seconds
    print(f'rx_pps={rx_pps}')

    tx_pps = (end_counts.tx_packets - start_counts.tx_packets) / args.seconds
    print(f'tx_pps={tx_pps}')
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Calculate Rx pps on interface')

    interface = 'eth1'
    seconds = 60

    parser.add_argument('--interface', default=interface, help=f'Interface. default --interface={interface}')
    parser.add_argument('--seconds', type=int, default=seconds, help=f'Seconds to count packets. default --seconds={seconds}')

    args = parser.parse_args()

    main(args)
