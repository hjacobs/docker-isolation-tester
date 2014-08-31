#!/usr/bin/env python3

import os
import sys
import signal
import time

n = int(sys.argv[1])

pids = []
for i in range(n):
    pid = os.fork()
    if pid == 0:
        time.sleep(10)
        sys.exit(0)
    print(i+1)
    pids.append(pid)

for pid in pids:
    os.kill(pid, signal.SIGTERM)

os.wait()
