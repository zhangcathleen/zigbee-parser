#!/usr/bin/env python3

import sys

ns_3_1 = []

ns_3_2 = []

ns_3_3 = []

ns_3_4 = []

rr_3_1 = []

rr_3_2 = []

rr_3_3 = []

rr_3_4 = []

f = open("results.txt", "r")
x = 0
for line in f:
    if x == 0:
        ns_3_1 = line
    elif x == 1:
        ns_3_2 = line
    elif x == 2:
        ns_3_3 = line
    elif x == 3:
        ns_3_4 = line
    elif x == 4:
        rr_3_1 = line
    elif x == 5:
        rr_3_2 = line
    elif x == 6:
        rr_3_3 = line
    elif x == 7:
        rr_3_4 = line
    x += 1
f.close()

# def main():
print("sth2-trios.pcap")
x = ""
while 1 == 1:
    x = input()
    if x in ns_3_1:
        print("network status 3 1")
    elif x in rr_3_1:
        print("route record 3 1")
    elif x in ns_3_2:
        print("network status 3 2")
    elif x in ns_3_3:
        print("network status 3 3")
    elif x in ns_3_4:
        print("network status 3 4")
    elif x in rr_3_2:
        print("route record 3 4")
    elif x in rr_3_3:
        print("route record 3 3")
    elif x in rr_3_4:
        print("route record 3 4 ")
    elif x == "q":
        sys.exit()
    else:
        print("not present")
        f = open("test.txt", "a")
        f.write(f"{x}\n")
        f.close()




# if __name__ == "main":
#     main()