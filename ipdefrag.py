#!/usr/bin/env python3
import argparse
import dpkt
import ipaddress

# Install dpkt: pip3 install dpkt

# The correct reassembly buffer is identified by an equality of
# the following fields:  the  foreign  and  local  internet  address,  the
# protocol ID, and the identification field.

class Fragment(object):
    def __init__(self, first, last, frag):
        self.first = first
        self.last = last
        self.frag = frag

class Hole(object):
    def __init__(self, first, last):
        self.first = first
        self.last = last

class ReassemblyEntry(object):
    def __init__(self, first_frag_size, protocol):
        self.buf = bytearray(first_frag_size) # // make the initial buf big enough to hold the first fragment
        self.hole_list = [ Hole(0, 65535) ]
        self.protocol = protocol

def make_ipv4_key(ip_src, ip_dst, protocol, identifier):
    return ip_src + ip_dst + protocol.to_bytes(1, 'big') + identifier.to_bytes(2, 'big')

def fix_IPv4_header(entry):
#   entry.ip._flags_offset = 0
    entry.ip.mf = 0
    entry.ip.offset = 0
    entry.ip.sum = 0

def make_ipv6_key(ip_src, ip_dst, protocol, identifier):
    return ip_src + ip_dst + protocol.to_bytes(1, 'big') + identifier.to_bytes(4, 'big')

def key_to_filter_str(key):
    '''print key as a Wireshark filter string'''
    if len(key) == 11: # IPv4
        ip_src = str(ipaddress.IPv4Address(key[0:4]))
        ip_dst = str(ipaddress.IPv4Address(key[4:8]))
        protocol = int(key[8])
        identifier = int.from_bytes(key[9:11], byteorder='big', signed=False)
        s = f'(ip.src == {ip_src}) && (ip.dst == {ip_dst}) && (ip.id == {identifier:#x})'
        return s
    if len(key) == 37: # IPv6
        ip_src = str(ipaddress.IPv6Address(key[0:16]))
        ip_dst = str(ipaddress.IPv6Address(key[16:32]))
        protocol = int(key[32])
        identifier = int.from_bytes(key[33:37], byteorder='big', signed=False)
        s = f'(ip.src == {ip_src}) && (ip.dst == {ip_dst}) && (ip.id == {identifier:#x})'
        return s
    return ''

def fix_IPv6_header(entry):
    '''Rebuild the IPv6 header preserving any extension headers except for the fragment header'''

    # build a list of all the IPv6 next header values excluding IP_PROTO_FRAGMENT
    next_header_list = []
    if entry.ip.nxt != dpkt.ip.IP_PROTO_FRAGMENT:
        next_header_list.append(entry.ip.nxt)
    for ext in entry.ip.all_extension_headers:
        if ext.nxt != dpkt.ip.IP_PROTO_FRAGMENT:
            next_header_list.append(ext.nxt)
 
    # fix the next header value in the IPv6 header with the first value from next_header_list.
    # It will either be that of the first remaining extension header or that of the payload.
    entry.ip.nxt = next_header_list.pop(0)
 
    # reset the payload length
    entry.ip.plen = 0
 
    # build a list of all the remaining extention headers excluding the fragment extension header.
    new_all_extension_headers = []
    for ext in entry.ip.all_extension_headers:
        if not isinstance(ext, dpkt.ip6.IP6FragmentHeader):
            # fix the next header for this extension header
            ext.nxt = next_header_list.pop(0)
            # add the length of this extension header to the IPv6 payload length
            entry.ip.plen += len(bytes(ext))
            new_all_extension_headers.append(ext)

    # replace the old extension header list with our new list
    entry.ip.all_extension_headers = new_all_extension_headers
 
    # add payload length to IPv6 payload length
    entry.ip.plen += len(entry.buf)
 
    # remove IP_PROTO_FRAGMENT from extension_hdrs map
    if dpkt.ip.IP_PROTO_FRAGMENT in entry.ip.extension_hdrs:
        del entry.ip.extension_hdrs[dpkt.ip.IP_PROTO_FRAGMENT]

class IpDefrag:
    def __init__(self):
        self.reassemblyMap = {}
        self.ipv4_fragments = 0
        self.ipv6_fragments = 0
        self.ipv4_defrag_count = 0
        self.ipv6_defrag_count = 0
        self.ipv4_defrag_max_mtu = 0
        self.ipv6_defrag_max_mtu = 0

    def defrag(self, eth, ip, more_fragments, fragment_offset, protocol, identifier, make_key, fix_ip_header):

        if more_fragments or fragment_offset != 0:
        #   print('more_fragments={0} fragment_offset={1} identifier={2}'.format(more_fragments, fragment_offset, identifier))
        #   print('ip.data={0}'.format(ip.data))

            first = fragment_offset
            frag = bytes(ip.data)
            last = fragment_offset + len(frag) - 1
            fragment = Fragment(first, last, frag)

            # Get the ReassemblyEntry
            key = make_key(ip.src, ip.dst, protocol, identifier)
        #   print('key={0}'.format(key))

            if key in self.reassemblyMap:
                entry = self.reassemblyMap[key]
            else:
                entry = ReassemblyEntry(fragment.last + 1, protocol)

            # save the Ethernet header and IP header from the first fragment
            if fragment_offset == 0:
                entry.eth = eth
                entry.ip = ip

            # based on this IP reassembly algorithm: https://datatracker.ietf.org/doc/html/rfc815

            new_hole_list = []

            for hole in entry.hole_list:

                if fragment.first > hole.last:
                    new_hole_list.append(hole)
                    continue
                elif fragment.last < hole.first:
                    new_hole_list.append(hole)
                    continue

                if fragment.first > hole.first:
                    new_hole = Hole(hole.first, fragment.first - 1)
                    new_hole_list.append(new_hole)

                if fragment.last < hole.last and more_fragments:
                    new_hole = Hole(fragment.last + 1, hole.last)
                    new_hole_list.append(new_hole)

            entry.hole_list = new_hole_list

            # grow the buffer if needed
            if fragment.last + 1 > len(entry.buf):
                grow = bytearray(fragment.last + 1)
                grow[0:len(entry.buf)] = entry.buf
                entry.buf = grow

            # copy the fragment into the buffer
            entry.buf[fragment.first:fragment.last+1] = fragment.frag

            if len(entry.hole_list) == 0: # reassembly is complete

                if key in self.reassemblyMap:
                    del self.reassemblyMap[key]

                fix_ip_header(entry)

                if entry.protocol == 6:
                    tcp = dpkt.tcp.TCP(entry.buf)
                    tcp.sum = 0
                    entry.ip.data = tcp
                elif entry.protocol == 17:
                    udp = dpkt.udp.UDP(entry.buf)
                    udp.sum = 0
                    entry.ip.data = udp
                elif entry.protocol == 132:
                    sctp = dpkt.sctp.SCTP(entry.buf)
                    sctp.sum = 0
                    entry.ip.data = sctp
    #           elif entry.protocol == 47:
    #               entry.ip.data = dpkt.gre.GRE(entry.buf)
                else:
                    entry.ip.data = entry.buf

                return entry.eth

            self.reassemblyMap[key] = entry

            return None

        return eth

    def process_eth(self, eth):
        ip = eth.data

        if isinstance(ip, dpkt.ip.IP):

            more_fragments = ip.mf == 1
            fragment_offset = ip.offset * 8
            protocol = ip.p
            identifier = ip.id
            make_key = make_ipv4_key
            fix_ip_header = fix_IPv4_header

            if more_fragments or fragment_offset > 0:
                self.ipv4_fragments += 1
                eth = self.defrag(eth, ip, more_fragments, fragment_offset, protocol, identifier, make_key, fix_ip_header)
                if eth != None:
                    self.ipv4_defrag_count += 1
                    if self.ipv4_defrag_max_mtu < len(eth):
                        self.ipv4_defrag_max_mtu = len(eth)

            return eth

        elif isinstance(ip, dpkt.ip6.IP6):

            if dpkt.ip.IP_PROTO_FRAGMENT in ip.extension_hdrs:
                fragHdr = ip.extension_hdrs[dpkt.ip.IP_PROTO_FRAGMENT]

                more_fragments = fragHdr.m_flag == 1
                fragment_offset = fragHdr.frag_off * 8
                protocol = ip.p
                identifier = fragHdr.id
                make_key = make_ipv6_key
                fix_ip_header = fix_IPv6_header

                if more_fragments or fragment_offset > 0:
                    self.ipv6_fragments += 1
                    eth = self.defrag(eth, ip, more_fragments, fragment_offset, protocol, identifier, make_key, fix_ip_header)
                    if eth != None:
                        self.ipv6_defrag_count += 1
                        if self.ipv6_defrag_max_mtu < len(eth):
                            self.ipv6_defrag_max_mtu = len(eth)

                return eth

        return eth

    def stats(self):
        '''Show defrag stats and traffic that could not be defragmented'''

        print(f'ipv4_fragments      : {self.ipv4_fragments}')
        print(f'ipv4_defrag_count   : {self.ipv4_defrag_count}')
        print(f'ipv4_defrag_max_mtu : {self.ipv4_defrag_max_mtu}')

        print(f'ipv6_fragments      : {self.ipv6_fragments}')
        print(f'ipv6_defrag_count   : {self.ipv6_defrag_count}')
        print(f'ipv6_defrag_max_mtu : {self.ipv6_defrag_max_mtu}')

        if len(self.reassemblyMap) > 0:
            print(f'Could not defragment:')
            for key in self.reassemblyMap:
                s = key_to_filter_str(key)
                print(f'{s}')


def process(reader, writer, args):

    defrag = IpDefrag()

    for ts, buf in reader:
    #   print('ts={0}'.format(ts))
        eth = dpkt.ethernet.Ethernet(buf)
    #   print('eth={0}'.format(eth))

        eth = defrag.process_eth(eth)
    #   print('eth={0}'.format(eth))

        if eth:
            writer.writepkt(bytes(eth), ts)

    if args.stats:
        defrag.stats()


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

    with open(args.inpcap, 'rb') as in_fh:
        with open(args.outpcap, 'wb') as out_fh:

            reader = pcap_pcapng_reader(in_fh)
            if reader:

                if args.outpcap.lower().endswith('.pcapng'):
                    writer = dpkt.pcapng.Writer(out_fh, snaplen=0xffff)
                else:
                    writer = dpkt.pcap.Writer(out_fh)

                process(reader, writer, args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='IP defragment a pcap')
    parser.add_argument('--stats', help='Show defrag stats and traffic that could not be defragmented', action='store_true')
    parser.add_argument('inpcap', help='input pcap file')
    parser.add_argument('outpcap', help='input pcap file')

    args = parser.parse_args()
#   print(args)

    main(args)

