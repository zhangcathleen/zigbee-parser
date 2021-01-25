#!/usr/bin/env python3

import sys
import os



def make_split(line):
    i = line[1:len(line)-2]
    j = i.replace("\'", "")
    m = j.split(", ")
    return m

def main():

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
            ns_3_1 = make_split(line)
        elif x == 1:
            ns_3_2 = make_split(line)
        elif x == 2:
            ns_3_3 = make_split(line)
        elif x == 3:
            ns_3_4 = make_split(line)
        elif x == 4:
            rr_3_1 = make_split(line)
        elif x == 5:
            rr_3_2 = make_split(line)
        elif x == 6:
            rr_3_3 = make_split(line)
        elif x == 7:
            rr_3_4 = make_split(line)
        x += 1
    f.close()

    try:
        os.remove("test.txt")
    except FileNotFoundError:
        pass

    x = ""
    while 1 == 1:
        x = input()
        if x in ns_3_1:
            print("network status 3 1")
            ns_3_1.remove(x)
        elif x in ns_3_2:
            print("network status 3 2")
            ns_3_2.remove(x)
        elif x in ns_3_3:
            print("network status 3 3")
            ns_3_3.remove(x)
        elif x in ns_3_4:
            print("network status 3 4")
            ns_3_4.remove(x)
        # if x in rr_3_1:
        #     print("route record 3 1")
        #     rr_3_1.remove(x)
        # elif x in rr_3_2:
        #     print("route record 3 4")
        #     rr_3_2.remove(x)
        # elif x in rr_3_3:
        #     print("route record 3 3")
        #     rr_3_3.remove(x)
        # elif x in rr_3_4:
        #     print("route record 3 4 ")
        #     rr_3_4.remove(x)
        elif x == "q":
            break
        elif x == "a":
            print(ns_3_1)
        else:
            print("not present")
            f = open("test.txt", "a")
            f.write(f"not present : {x}\n")
            f.close()

    # joined = ns_3_1 + ns_3_2 + ns_3_3 + ns_3_4 + rr_3_4 + rr_3_3 + rr_3_2 + rr_3_1
    joined = ns_3_1 + ns_3_2 + ns_3_3 + ns_3_4
    # joined = rr_3_1 + rr_3_2 + rr_3_3 + rr_3_4

    f = open("test.txt", "a")
    f.write("not accounted\n")
    for x in joined:
        f.write(f"{x}\n")
    f.close()





if __name__ == "__main__":
    main()