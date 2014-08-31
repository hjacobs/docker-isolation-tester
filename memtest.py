#!/usr/bin/env python3

import psutil
import sys

MIB = 1024*1024

mem = int(sys.argv[1])

chunks = [None] * (mem // MIB)

proc = psutil.Process()
mi = proc.memory_info()
print(mi.rss, mi.vms)

for i in range(len(chunks)):
    data = b'0' * MIB
    chunks[i] = data
    mi = proc.memory_info()
    print(mi.rss, mi.vms)
    if mi.vms > mem:
        break

