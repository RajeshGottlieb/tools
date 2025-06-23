#!/usr/bin/env python3
import argparse
import socket
import struct
import time

# Poor man's time sync
#
# now=`sntp.py`; date --set="$now"
# or
# sntp.py > /tmp/now; date --set="`cat /tmp/now`"; rm /tmp/now

#ntp_server = '172.18.18.18'
ntp_server = '10.144.196.250'
#ntp_server = '10.152.196.250'


def main(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    leap_indicator = 0
    version = 4
    mode = 3 # client
    flags = (leap_indicator & 0x03) << 6 | (version & 0x07) << 3 | (mode & 0x07)

    ntp_msg = struct.pack('>BBBBIIIIIIIIIII', flags, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    sock.sendto(ntp_msg, (args.server, args.port))

    data, addr = sock.recvfrom(1024)
    sock.close()

    (flags, stratum, polling, precision, root_delay, root_dispersion, ref_id,
     ref_sec, ref_frac,
     origin_sec, origin_frac,
     receive_sec, receive_frac,
     transmit_sec, transmit_frac) = struct.unpack('>BBBBIIIIIIIIIII', data);

    seconds_1970 = 2208988800 # NTP time is relative to 0h on 1 January 1900. see: https://tools.ietf.org/html/rfc868
    unix_sec = receive_sec - seconds_1970
#   print(unix_sec)

    print(time.strftime('%a %b %d %H:%M:%S %Z %Y', time.localtime(unix_sec)))


if __name__ == '__main__':
    # parse command line arguments
    parser = argparse.ArgumentParser(description='get time from NTP server')

    parser.add_argument('--port', type=int, help='NTP server port', default=123)
    parser.add_argument('--server', help=f'NTP server. default --server={ntp_server}', default=ntp_server)

    args = parser.parse_args()

#   print('args={0}'.format(args))

    main(args)
