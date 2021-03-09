#!/usr/bin/env python
from threading import Thread
import re,subprocess
from Queue import Queue

verbose = False

num_threads = 4
queue = Queue()
inactive_ips = [0 for i in range(256)]

config_list = list(subprocess.check_output("ls -A1 /etc/vz/conf/*.conf", stderr=subprocess.STDOUT, shell=True).split('\n'))
used_ips=[]

for config in config_list:
    if config != '':
        with open(config) as cf:
            cstring = cf.readlines()
            for line in cstring:
                ips = re.findall("10.124.156."+r'\d{1,3}', line)
                for ip in ips:
                    used_ips.append(ip)

lines = open("/proc/net/arp", "r").readlines()
arp_cache = [l.split()[0] for l in lines[1:] if l.split()[2] == "0x2"]
used_ips = used_ips + arp_cache

def ip_str_to_int(ip):
    ip = ip.rstrip().split('.')
    ipn = 0
    while ip:
        ipn = (ipn << 8) + int(ip.pop(0))
    return ipn

def ip_int_to_str(ip):
    ips = ''
    for i in range(4):
        ip, n = divmod(ip, 256)
        ips = str(n) + '.' + ips
    return ips[:-1] ## take out extra point

if __name__ == '__main__':
    from optparse import OptionParser
    usage = "usage: %prog [options] [first IP] [last IP]"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="make lots of noise")
    parser.add_option("-q", action="store_false", dest="verbose", help="print only IP adresses")
    (options, args) = parser.parse_args()
    verbose = options.verbose

    first = ip_str_to_int(args[0] if len(args) > 0 else "192.168.0.1")
    last = ip_str_to_int(args[1] if len(args) > 1 else "192.168.0.254")

for ip in range(first, last +1):
    ip = ip_int_to_str(ip)
    if ip not in used_ips:
        ret = subprocess.call("ping -c 1 %s" % ip,
            shell=True,
            stdout=open('/dev/null', 'w'),
            stderr=subprocess.STDOUT)
        if ret != 0:
#            ip = ip_int_to_str(ip)
            print ip
            exit()
