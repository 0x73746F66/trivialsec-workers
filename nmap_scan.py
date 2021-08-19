import nmap
import argparse
import termios
import fcntl
import sys
import os
from datetime import datetime


parser = argparse.ArgumentParser()
parser.add_argument('-i --ip', help='host ip to scan', dest='ip')
args = parser.parse_args()
ip = args.ip
if not ip:
    print('host ip must be provided')
    sys.exit(1)


def get_items(dict_object):
    for key in dict_object:
        yield key, dict_object[key]


def scan_cb(host, result):
    state = result['scan'][host]['status']['state']
    hostname = result['scan'][host]['hostnames'][0]['name']
    print("[%s] Host: %s (%s)" % (state, hostname, host))

    for port, p in get_items(result['scan'][host]['tcp']):
        port_state = p['state']
        port_name = p['product']
        port_info = "%s %s" % (p['reason'], p['extrainfo'])
        print('[%s] Port %d: %s (%s)' %
              (port_state, port, port_name, port_info))


fd = sys.stdin.fileno()

oldterm = termios.tcgetattr(fd)
newattr = termios.tcgetattr(fd)
newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
termios.tcsetattr(fd, termios.TCSANOW, newattr)

oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)

try:
    nm = nmap.PortScannerAsync()
    nm.scan(ip, '20-23,25,53,57,67-69,80,81,82,107-113,115,118-119,135,137-139,143,153,156,170,177,179,194,209,213,218,220,300,311,366,369-371,383,384,387,389,399,427,433,434,443-445,464,465,475,491,514,515,517,518,520,521,524,530-533,540,546-548,556,560,561,563-585,587,591,593,601,604,623,625,631,635,636,639,641,646-648,653-655,657,660,666,674,688,690,691,706,711,712,749-754,760,782,783,808,832,843,847,848,873,953-61000', callback=scan_cb)
    start_time = datetime.utcnow()
    while nm.still_scanning():
        stop_time = datetime.utcnow()
        elapsed = stop_time - start_time
        try:
            c = sys.stdin.read(1)
            if str(c) == 's':
                print("elapsed %ds" % elapsed.seconds)
        except IOError:
            pass
        nm.wait(1)

finally:
    termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
    fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)
