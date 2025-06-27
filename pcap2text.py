#!/usr/bin/env python3
import argparse
import dpkt
import time
import re

timeformat = "%Y-%m-%d %H:%M:%S"

def to_printable_ascii(byte):
    return chr(byte) if 32 <= byte <= 126 else '.'

def hex_dump(out_fh, pkt_bytes):
    offset = 0
    while offset < len(pkt_bytes):
        chunk = pkt_bytes[offset:offset+16]
        hex_values = ' '.join(f"{byte:02x}" for byte in chunk)
        ascii_values = ''.join(to_printable_ascii(byte) for byte in chunk)
        out_fh.write(f'{offset:06x}  {hex_values:<48}  {ascii_values}\n')
        offset += 16
    out_fh.write(f'\n')


def time2string(seconds_float):
    seconds, sub_seconds = str(seconds_float).split('.') 
    time_tuple = time.gmtime(int(seconds))
    time_str = time.strftime(timeformat, time_tuple)
    if sub_seconds:
        time_str = time_str + '.' + sub_seconds
    return time_str


def process(reader, out_fh):

    for ts, pkt in reader:

        timestamp = time2string(ts)
        out_fh.write(f'{timestamp}\n')

        hex_dump(out_fh, pkt)


def pcap_pcapng_reader(in_fh):
    '''Try to open as pcap or pcapng file'''
    try:
        reader = dpkt.pcap.Reader(in_fh)
        return reader
    except ValueError:
        try:
            in_fh.seek(0)
            reader = dpkt.pcapng.Reader(in_fh)
            return reader
        except ValueError:
            print(f'file does not appear to be a pcap or pcapng file')
    return None


def main(args):

    with open(args.inpcap,'rb') as in_fh:
        with open(args.outtext,'w') as out_fh:

            reader = pcap_pcapng_reader(in_fh)
            if reader:

                out_fh.write('# Convert back to pcap:\n')
                out_fh.write(f'# text2pcap -t "{timeformat}" {args.outtext} <out-pcap>\n\n')

                process(reader, out_fh)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Write text file from pcap (opposite of text2pcap)')
    parser.add_argument('inpcap', help='input pcap file')
    parser.add_argument('outtext', help='output text file')

    args = parser.parse_args()
#   print(args)

    main(args)

