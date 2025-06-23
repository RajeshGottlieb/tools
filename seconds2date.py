#!/usr/bin/env python3
import sys
import time

seconds = int(float(sys.argv[1]))
date_str = time.ctime(seconds)

print(date_str)
