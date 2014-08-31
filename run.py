#!/usr/bin/env python3

import argparse
import logging
import os
import psutil
import resource
import re
import netaddr
import subprocess
import time

DRY_RUN = False

def real_run():
    if DRY_RUN:
        print('** DRY-RUN **')
        return False
    return True

def test_hostname():
    with open('/etc/hostname') as fd:
        hostname = fd.read().strip()
    logging.info('Hostname is %s', hostname)

def test_user():
    p = psutil.Process()
    logging.info('Running as %s', p.username())

def test_resolvconf():
    with open('/etc/resolv.conf') as fd:
        resolv = fd.read().strip()
    logging.info('resolv.conf is %s', resolv)

def test_dns():
    import socket
    socket.gethostbyname('google.com')

def test_disk():
    logging.info('Checking whether writing to / is possible..')
    if real_run():
        with open('/test-file', 'wb') as fd:
            fd.write(1)

def test_mounts():
    with open('/proc/mounts') as fd:
        for line in fd:
            logging.debug('%s', line.strip())

def test_diskio():
    fn = '/tmp/ddtest'
    start = time.time()
    bs = 4096
    count = 400000
    if real_run():
        subprocess.check_call('dd if=/dev/zero of={} bs={} count={} && sync'.format(fn, bs, count), shell=True)
        duration = time.time() - start
        bytes_per_sec = (bs*count)/duration
        logging.info('File write took %.2f seconds (%d MiB/s)', duration, bytes_per_sec // (1024*1024))
        os.unlink(fn)

def test_fork():
    limits = resource.getrlimit(resource.RLIMIT_NPROC)
    maxprocs = min(limits[1], 1024)
    cmd = os.path.join(os.path.dirname(__file__), 'fork.py')
    logging.info('Trying to fork %d processes..', maxprocs)
    if real_run():
        try:
            subprocess.check_call('{} {} > /tmp/fork.log'.format(cmd, maxprocs), shell=True, timeout=60)
        except Exception:
            logging.exception('Failed to fork')
        with open('/tmp/fork.log') as fd:
            allocated = fd.readlines()[-1].strip()
        logging.info('Forked %s processes', allocated)

def test_rlimits():
    for k, v in sorted(resource.__dict__.items()):
        if k.startswith('RLIMIT_'):
            val = resource.getrlimit(v)
            logging.info('%s: %s', k, val)

    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    maxfiles = min(limits[1], 8192)
    logging.info('Trying to open %d files..', maxfiles)
    if real_run():
        i = 0
        try:
            # list is needed to keep files open (prevent GC)
            handles = []
            for i in range(maxfiles):
                fd = open('/tmp/file-{}'.format(i), 'w')
                fd.write('1')
                handles.append(fd)
                if i > 0 and i % 1000 == 0:
                    logging.debug('Opened %d files', i)
        except IOError:
            logging.exception('Could open %s files', i)
        for i in range(maxfiles):
            try:
                os.unlink('/tmp/file-{}'.format(i))
            except:
                pass

def test_cpu():
    logging.info('Running CPU benchmark..')
    out = subprocess.check_output(['sysbench', '--test=cpu', '--cpu-max-prime=10000', 'run'])
    for line in out.splitlines():
        line = line.strip().decode('utf-8')
        if line.startswith('total time:'):
            total_time = line.split(':')[-1].strip()
            logging.info('CPU benchmark took %s', total_time)

def test_memory():
    import psutil
    MiB = 1024*1024
    MB = 1000*1000
    mem = psutil.virtual_memory().total
    logging.info('Memory: %d MiB (%d MB)', mem // MiB, mem // MB)
    logging.info('Trying to allocate %s Bytes..', mem)
    cmd = os.path.join(os.path.dirname(__file__), 'memtest.py')
    if real_run():
        try:
            subprocess.check_call('{} {} > /tmp/memtest.log'.format(cmd, mem), shell=True)
        except Exception:
            logging.exception('Failed to allocate memory')
        with open('/tmp/memtest.log') as fd:
            allocated = fd.readlines()[-1].strip()
        logging.info('Could allocate %s', allocated)

def test_internet():
    import socket
    # Google DNS server
    addr = ('8.8.8.8', 53)
    logging.info('Checking connect to %s..', addr)
    sock = socket.create_connection(addr, 5)

def test_network():
    import netifaces
    import nmap
    print(netifaces.gateways())
    for iface in netifaces.interfaces():
        logging.info('Found interface %s', iface)
        if iface == 'lo':
            continue
        addrs = netifaces.ifaddresses(iface)
        print(addrs)
        for a in addrs[netifaces.AF_INET] + addrs[netifaces.AF_INET6]:
            nm = nmap.PortScanner()
            # somehow we can IPv6 addresses with '%eth0' suffix
            ip = re.sub('%.*', '', a['addr'])
            net = netaddr.IPNetwork('{}/{}'.format(ip, a['netmask']))
            logging.info('Found address %s', net)
            #nm.scan(hosts=str(net), arguments='-sn -PE')
            #print(nm.all_hosts())


def make_action(funcs, f):
    class customAction(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            funcs.remove(f)
    return customAction

def add(funcs, f):
    class customAction(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            funcs.append(f)
    return customAction

def main():
    global DRY_RUN

    functions = []
    for name in globals().keys():
        if name.startswith('test_'):
            f = globals().get(name)
            functions.append(f)
    all_functions = sorted(functions, key=lambda f: f.__name__)
    parser = argparse.ArgumentParser()
    for f in all_functions:
        parser.add_argument('--no-{}'.format(f.__name__[len('test_'):]), nargs=0, action=make_action(functions, f))
    for f in all_functions:
        parser.add_argument('--with-{}'.format(f.__name__[len('test_'):]), nargs=0, action=add(functions, f))

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-v', '--verbose', help='Verbose (debug) logging', action='store_const', const=logging.DEBUG,
                            dest='loglevel')
    group.add_argument('-q', '--quiet', help='Silent mode, only log warnings', action='store_const',
                            const=logging.WARN, dest='loglevel')
    parser.add_argument('--dry-run', help='Noop, do not write anything', action='store_true')
    args = parser.parse_args()

    DRY_RUN = args.dry_run

    logging.basicConfig(level=args.loglevel or logging.INFO)

    if len(functions) > len(all_functions):
        functions = functions[len(all_functions):]

    for f in sorted(functions, key=lambda f: f.__name__):
        logging.info('Running %s..', f.__name__)
        try:
            f()
        except Exception as e:
            print('ERROR', e)

if __name__ == '__main__':
    main()
