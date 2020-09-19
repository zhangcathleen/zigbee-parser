#!/usr/bin/env python3

import sys

x = 0

def a():
  if len(sys.argv) == 2:
      print(sys.argv)
  else:
    return print("hi")

try:
  while True:
    a()
except KeyboardInterrupt:
    print("caught keyboard interrupt excep")
else:
    print("no exceps caught")
  
