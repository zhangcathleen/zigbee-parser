#!/usr/bin/env python3

import sys

x = 0
a = {1, 2, 3}
b = 3
#c = set((3))

"""
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
"""

#ca = c.isdisjoint(a)
#ac = a.isjoint(c)
##print(f"{1, 2, 3} is disjoint from 3? {a.isdisjoint(b)}")
#print(f"{3} is disjoint from {1, 2, 3}? ")
#print(ca)
#print(f"{1, 2, 3} is disjoint from {3}? ")
#print(ac)

#while x < 10:
#  if x == 5:
#    pass
#  elif x== 7:
#    continue
#  elif x == 9:
#    break
#  x = x+1
#  print(x)


#apple = {1:'a', 2:'b', 3:'c'}
#print(list(apple.keys()))
#for seed, core in apple.items():
#  print(seed)
#  print(core)

test1 = {"hi" : ("yes", "no")}
test2 = {"hi2" : "yes2"}

a = "hi"

test1[f'{a}'] = 

for k, v in test1.items():
  print(f'key {k} : val {type(v)}')

for k, v in test2.items():
  print(f'key {k} : val {type(v)}')
