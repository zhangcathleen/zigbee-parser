#!/usr/bin/python3

import csv
import sys
import pyshark
from scapy.all import *
import time


# TODO : progress bar instead of printing out all of the frame numbers
#       instead, print the results into a file
#       file will only be a thing if the entire thing finishes? Or maybe I should be able to let it go until it parses through
# TODO : an all in 1 testing everything
# TODO : end device timeout response
# TODO : end device timeour response

# network_report + link_status + route_reply
# stored as 16 bit
zbee_r = {"hi"}

# src: network update + route reply + rejoin response + link status
# stored as 16bit
zbee_c = {"hi"}

# route request + network status + leave + route record + rejoin request
# what is leftover - not zbee routers or coordinators
not_coord = {"hi"}

# what are the end device srcs
# done in print_zed()
# stored as 16bit
zbee_ed = {"hi"}

start_time = 0

done = {""}

# more_parse ------------------------------------------------------------------------


"""
  Parses the next command/packet based on user input
"""
def more_parse():

  doc = "\n====================\n====================\n  OPTIONS:\n         --routeRequest\n         --rejoinResponse\n         --linkStatus\n         --networkUpdate\n         --routeReply\n         --networkReport\n         --endDeviceTimeoutRequest [edtRequest]\n         --endDeviceTimeoutResponse [edtResponse]\n\n         zc        -print out the extended addr of zigbee coordators\n\n         zr        -print out the short addr of zigbee routers\n\n         zed       -print out the short addr of zigbee end devices\n\n   STOP:\n       Ctrl + C\n\n   PRINT PACKET TYPES:\n      use 'done' to print which packets have already been scanned\n\n   QUIT:\n      use 'quit' to exit\n\n   HELP:\n      use 'help' to print this menu\n====================\n====================\n\n"

  print(doc)
  try:
    while True:
      option = input()
      if (option == '--routeRequest') or (option == '--routerequest') or (option == '--RouteRequest') or (option == 'routeRequest') or (option == 'routerequest') or (option == 'RouteRequest'):
        return count_route_request()
      elif (option == '--rejoinResponse') or (option == '--rejoinresponse') or (option == '--RejoinResponse') or (option == 'rejoinResponse') or (option == 'rejoinresponse') or (option == 'RejoinResponse'):
        return count_rejoin_response()
      elif (option == '--linkStatus') or (option == '--linkstatus') or (option == '--LinkStatus') or (option == 'linkStatus') or (option == 'linkstatus') or (option == 'LinkStatus'):
        return count_link_status()
      elif (option == '--networkUpdate') or (option == '--networkupdate') or (option == '--NetworkUpdate') or (option == 'networkUpdate') or (option == 'networkupdate') or (option == 'NetworkUpdate'):
        return count_network_update()
      elif (option == '--routeReply') or (option == '--routereply') or (option == '--RouteReply') or (option == 'routeReply') or (option == 'routereply') or (option == 'RouteReply'):
        return count_route_reply()
      elif (option == '--networkReport') or (option == '--networkreport') or (option == '--NetworkReport') or (option == 'networkReport') or (option == 'networkreport') or (option == 'NetworkReport'):
        return count_network_report()
      elif (option == '--endDeviceTimeoutRequest') or (option == '--enddevicetimeoutrequest') or (option == '--EndDeviceTimeoutRequest') or (option == 'edtrequest') or (option == '--edtRequest') or (option == 'endDeviceTimeoutRequest') or (option == 'enddevicetimeoutrequest') or (option == 'EndDeviceTimeoutRequest') or (option == 'edtRequest'):
        print("\nanalyzing end device timeout request packets\n")
        return 7
      elif (option == '--endDeviceTimeoutResponse') or (option == '--enddevicetimeoutresponse') or (option == '--EndDeviceTimeoutResponse') or (option == 'edtresponse') or (option == '--edtResponse') or (option == 'endDeviceTimeoutResponse') or (option == 'enddevicetimeoutresponse') or (option == 'EndDeviceTimeoutResponse') or (option == 'edtResponse'):
        print("\nanalyzing end device timeout response packets\n")
        return 8
      elif (option == 'zr') or (option == 'ZR') or (option == 'zR') or (option == 'Zr'):
        print_zr()
      elif (option == 'zc') or (option == 'ZC') or (option == 'zC') or (option == 'Zc'):
        print_zc()
      elif (option == 'zed') or (option == 'zeD') or (option == 'zEd') or (option == 'zED') or (option == 'ZED') or (option == 'ZEd') or (option == 'ZeD'):
        print_zed()
      elif (option == 'done') or (option == 'd'):
        print_done()
      elif (option == 'help') or (option == 'h') or (option == 'Help'):
        print(doc)
      elif (option == 'quit'):
        print("\n\nquiting the program\nbye!\n")
        sys.exit()
      else:
        continue
  except KeyboardInterrupt:
    print("\n\n(system interrupt) use quit to exit")

# parse ------------------------------------------------------------------------


"""
  Parses through the command line arguments to determine which packet to count
"""
def parse():

  no = len(sys.argv)

  if no == 2:
    option = sys.argv[1]
    if (option == '--routeRequest') or (option == '--routerequest') or (option == '--RouteRequest'):
      return count_route_request()
    elif (option == '--rejoinResponse') or (option == '--rejoinresponse') or (option == '--RejoinResponse'):
      return count_rejoin_response()
    elif (option == '--linkStatus') or (option == '--linkstatus') or (option == '--LinkStatus'):
      return count_link_status()
    elif (option == '--networkUpdate') or (option == '--networkupdate') or (option == '--NetworkUpdate'):
      return count_network_update()
    elif (option == '--routeReply') or (option == '--routereply') or (option == '--RouteReply'):
      return count_route_reply()
    elif (option == '--networkReport') or (option == '--networkreport') or (option == '--NetworkReport'):
      return count_network_report()
    elif (option == '--endDeviceTimeoutRequest') or (option == '--enddevicetimeoutrequest') or (option == '--EndDeviceTimeoutRequest') or (option == 'edtrequest') or (option == '--edtRequest'):
      return 7
    elif (option == '--endDeviceTimeoutResponse') or (option == '--enddevicetimeoutresponse') or (option == '--EndDeviceTimeoutResponse') or (option == 'edtresponse') or (option == '--edtResponse'):
      return 8
    else:
      more_parse()
  else:
    more_parse()


"""
  Device-maps the devices
"""

# done  ------------------------------------------------------------------------

"""
  Prints out the packets that have been scanned
"""
def print_done():
  for x in done:
    print(x)

# start ------------------------------------------------------------------------


"""
  Sets the start_time to the clock
"""
def start():
  global start_time
  start_time = time.clock()

# finish ------------------------------------------------------------------------


"""
  Ouputs the time elapsed
"""
def finish():
  #print(start_time)
  print(f"time it took to run this command: {(time.clock() - start_time)/60} min")

# print_zed ------------------------------------------------------------------------


"""
  Output the current zigbee addresses that are thought to be zigbee end devices
"""
def print_zed():
    print("\n\n=======")
    print(f"zigbee end devices [so far]: {zbee_ed}")
    print("======\n\n")

# print_zr ------------------------------------------------------------------------


"""
  Outputs the current zigbee addresses that are thought to be zigbee routers
"""
def print_zr():
  print("\n\n=======")
  print(f"zigbee router addresses [so far]: {zbee_r}")
  print("======\n\n")

# print_zc ------------------------------------------------------------------------


"""
  Outputs the current zigbee addresses that are thought to be zigbee coordinators
"""
def print_zc():
  print("\n\n=====")
  print(f"zigbee coordinator addresses [so far]: {zbee_c}")
  print("=====\n")

# count_rejoin_response ------------------------------------------------------------------------


"""
  Counts the number of rejoin response packets in the pcap file
  src : zc, zr
  dst : zr, zed
"""
def count_rejoin_response():
  print("\nanalyzing for rejoin response packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  """
    count should represent how many packets of that type are
  """
  count = 0 

  # this is so we can print the routers + coordinates + end devices so I can print which ones
  leftovers = {"hi"}
  routers = {"hi"}
  coords = {"hi"}
  try:
    for pk in shark_cap:
      """
        Try because you could get attribute error - a packet w/no zbee layer
      """
      try:
        if 'zbee_nwk' in dir(pk):
          zbee = pk.zbee_nwk
          if (zbee.frame_type == '0x00000001') and (zbee.radius == '1') and (zbee.data_len == '4'):
            """
              Printing the frame number -> cross reference w/ Wireshark what the packet is
            """
            frame = pk.frame_info
            print(frame.number)
            count = count + 1
            """
              For device mapping - getting all of the zigbee router extended src address
            """
            # not 0x0000 0000 because that's the zigbee coordinator (which should all be already identifiedaas 0x0000
            if zbee.src != '0x00000000':
              routers.add(zbee.src)
            else:
              coords.add(zbee.src64)
            # can't distinguish between zc + zr, so we'll do it at the end of the program
            leftovers.add(zbee.dst)
      except AttributeError:
        pass
  except KeyboardInterrupt:
    print("\n\n==INTERRRUPPTEDDDD==\n")
    print(f"number of rejoin response packets up to the previous number: {count}")
#    print(f"")
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
#    print(zbee_r)
    finish()
    more_parse()
  else:
    # distinguishing between zc + zr
    print(f"total number of rejoin response packets : {count}\n")
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")

    print(f"router addresses: {routers}\n")
    zbee_r.update(routers)

    print(f"coordinator addresses : {coords}\n")
    zbee_c.update(coords)

    ends = leftovers.difference(zbee_r)
    print(f"end device addresses : {ends}\n")
    zbee_ed.update(ends)

    finish()
    # to help understand what commands have already been called
    done.add("rejoin_response")
    more_parse()


# count_route_request ------------------------------------------------------------------------


"""
  Counts the number of route request packets in the pcap file
  src : zc, zr, zed
  dest : 0xfffc
"""
def count_route_request():
  if len(zbee_r) <= 1:
    print("\n\n=======")
    print("not enough information\nrun some more tests before this one please    thanks!")
    print("======\n\n")
    more_parse()
  print("\nanalyzing for route request packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  """
    count should represent how many packets of that type are
  """
  count = 0
  leftovers = {"hi"}
  coords = {"hi"}
  try:
    for pk in shark_cap:
      """
        Try because you could get attribute error - a packet w/no zbee layer
      """
      try:
        if 'zbee_nwk' in dir(pk):
          zbee = pk.zbee_nwk
          if (zbee.frame_type == '0x00000001') and (zbee.radius != '1') and (zbee.dst == '0x0000fffc'):
            """
              Printing the frame number -> cross reference w/ Wireshark what the packet is
            """
            frame = pk.frame_info
            print(frame.number)
            count = count + 1
            # if this is a zigbee coordinator
            if zbee.src == '0x00000000':
              coords.add(zbee.src64)
            # a zigbee coord or zigbee end device
            else:
              leftovers.add(zbee.src)
      except AttributeError:
        pass
  except KeyboardInterrupt:
    print("\n\n==INTERRRUPPTEDDDD==\n")
#    print(f"number of route request packets up to the previous number: {count}")
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
#    print(zbee_r)
    finish()
    more_parse()
  else:
    print(f"total number of route request packets : {count}")
#    not stating the number of zbee routers here bc there isn't a separation between the zbee routers + end devices
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
#    print(zbee_r)
    
    print(f"coordinator addresses : {coords}\n")
    zbee_c.update(coords)

    ends = leftovers.difference(zbee_r)
    print(f"end device addresses : {ends}\n")
    zbee_ed.update(ends)

    routers = leftovers.difference(zbee_ed)
    print(f"router addresses : {routers}\n")
    zbee_r.update(routers)

    finish()
    # to help understand what commands have already been called
    done.add("route request")
    more_parse()

# count_link_status ------------------------------------------------------------------------


"""
  Counts the number of link status packets in the pcap file
  Dst : 0xfffc
  Src : zig_coordinator + zig_router
  will add zbee routers to zbee_r [set]
"""
def count_link_status():
  start()
  print("\nanalyzing for link status packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  """
    count should represent how many packets of that type are
  """
  count = 0 
  routers = {"hi"}
  coords = {"hi"}
  """
    Try because you could get attribute error - a packet w/no zbee layer
  """
  try:
    # `for` needs to be inside of `try` because exception `bubbles` up to `try`
    # but if `try` is inside of `for` loop, it will be consumed
    for pk in shark_cap:
      try:
        if 'zbee_nwk' in dir(pk):
          zbee = pk.zbee_nwk
          if (zbee.frame_type == '0x00000001') and (zbee.radius == '1') and (zbee.dst == '0x0000fffc'):
            """
              Printing the frame number -> cross reference w/ Wireshark what the packet is
            """
            frame = pk.frame_info
            print(frame.number)
            count = count + 1
            """
              For device mapping - getting all of the zigbee router extended src address
            """
            # not 0x0000 0000 because that's the zigbee coordinator (which should all be already identifiedaas 0x0000
            if zbee.src != '0x00000000':
              routers.add(zbee.src)
            else:
              coords.add(zbee.src64)
      except AttributeError:
        pass
  except KeyboardInterrupt:
    print("\n\nINTERRRUPPTEDDDD")
#    print(f"number of link status packets up to the previous number: {count}")
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
#    print(zbee_r)
    finish()
    more_parse()
  else:
    print(f"total number of link status packets : str(count)")
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
#    print(zbee_r)
    print(f"router addresses: {routers}\n")
    zbee_r.update(routers)

    print(f"coordinator addresses : {coords}\n")
    zbee_c.update(coords)

    finish()
    # to help understand what commands have already been called
    done.add("link_status")
    more_parse()

# count_network_update ------------------------------------------------------------------------
#TODO: get the destination

"""
  Counts the number of network update packets in the pcacp file
  dst : 0xfffc
  src : zc
"""
def count_network_update():
  start()
  print("\nanalyzing for network update packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  """
    count should represent how many packets of that type are
  """
  count = 0 
  coords = {"hi"}
  """
    Try because you could get attribute error - a packet w/no zbee layer
  """
  try:
    for pk in shark_cap:
      try:
        zbee = pk.zbee_nwk
        if (zbee.frame_type == '0x00000001') and (zbee.data_len == '13'):
          """
            Printing the frame number -> cross reference w/ Wireshark what the packet is
          """
          frame = pk.frame_info
          count = count + 1
          print(frame.number)
          coords.add(zbee.src64)
      except AttributeError:
        continue
  except KeyboardInterrupt:
    print("\n\nINTERRRUPPTEDDDD")
#    print(f"number of network update packets up to the previous number: {count}")
#    print(f"zbee coordinators [{len(zbee_c) - 1}] : ", end = " ")
#    print(zbee_c)
    finish()
    more_parse()
  else:
    print(f"total number of network update packets : {str(count)}")
#    print(f"zbee coordinators [{len(zbee_c) - 1}] : ", end = " ")
#    print(zbee_c)

    print(f"coordinator addresses: {coords}\n")
    zbee_r.update(coords)

    finish()
    # to help understand what commands have already been called
    done.add("network_update")
    more_parse()

# count_route_reply ------------------------------------------------------------------------

"""
  Counts the number of route reply packets in the pcacp file
  Destination = ZC || ZR
  Source = ZC || ZR
  adds zbee routers to zbee_r
"""
def count_route_reply():
  start()
  print("\nanalyzing for route reply packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  count = 0 
  routers = {"hi"}
  coords = {"hi"}
  """
    Try because you could get attribute error - a packet w/no zbee layer
  """
  try:
    """
      count should represent how many packets of that type are
    """
    for pk in shark_cap:
      try:
        if 'zbee_nwk' in dir(pk):
          zbee = pk.zbee_nwk
          wpan = pk.wpan
          if (zbee.frame_type == '0x00000001') and (zbee.radius != '1') and (wpan.src16 == zbee.src) and (zbee.ext_dst == '1') and ((zbee.data_len == '8') or (zbee.data_len == '16') or (zbee.data_len == '24')):
            """
              Printing the frame number -> cross reference w/ Wireshark what the packet is
             """
            frame = pk.frame_info
            print(frame.number)
            count = count + 1
            # not 0x0000 0000 because that's the zigbee coordinator - which should all be already identified as 0x0000
            if zbee.src != '0x00000000':
              routers.add(zbee.src)
            # adding the 64 address into the zigbee coordinators
            else:
              coords.add(zbee.src64)
            if zbee.dst != '0x00000000':
              routers.add(zbee.dst)
            # adding the 64 address into the zigbee coordinators
            else:
              coords.add(zbee.dst64)
      except AttributeError:
        pass
  except KeyboardInterrupt:
    print("\n\nINTERRRUPPTEDDDD")
#    print(f"number of route reply packets up to the previous one: {count}")
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
#    print(zbee_r)
    finish()
    more_parse()
  else:
    print(f"total number of route reply packets : {count}")
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
#    print(zbee_r)
    print(f"router addresses: {routers}\n")
    zbee_r.update(routers)

    print(f"coordinator addresses : {coords}\n")
    zbee_c.update(coords)

    finish()
    # to help understand what commands have already been called
    done.add("route_reply")
    more_parse()

# count_network_report ------------------------------------------------------------------------


"""
  Counts the number of network report packets in the pcacp file
  destination : zc = 0x0000
  source : zr 
  will add source (zbee routers) to zbee_r [set]
"""
def count_network_report():
  start()
  print("\nanalyzing network report packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  """
    count should represent how many packets of that type are
  """
  count = 0 
  coords = {"hi"}
  routers = {"hi"}
  """
    Try because you could get attribute error - a packet w/no zbee layer
  """
  try:
    for pk in shark_cap:
      try:
        if 'zbee_nwk' in dir(pk):
          zbee = pk.zbee_nwk
          wpan = pk.wpan
          if (zbee.frame_type == '0x00000001') and (zbee.radius != '1') and (zbee.ext_dst == '0') and (zbee.dst == '0x00000000'):
            """
              Printing the frame number -> cross reference w/ Wireshark what the packet is
            """
            frame = pk.frame_info
            print(frame.number)
            count = count + 1
#            print(count)
#            print(f"zbee.src : {zbee.src}")
            routers.add(zbee.src)
            if zbee.dst == "0x0000":
              coords.add(zbee.dst64)
      except AttributeError:
        pass
  except KeyboardInterrupt:
    print("\n\nINTERRRUPPTEDDDD")
#    print(f"number of network report packets up to the previous packet: {count}")
#    print(f"zbee routers {len(zbee_r) - 1} : ", end = " ")
#    print(zbee_r)
    finish()
    more_parse()
  else:
    print(f"total number of network report packets {str(count)}")
#    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
#    print(zbee_r)

    print(f"router addresses: {routers}\n")
    zbee_r.update(routers)

    print(f"coordinator addresses : {coords}\n")
    zbee_c.update(coords)

    finish()
    # to help understand what commands have already been called
    done.add("network_report")
    more_parse()

# main ------------------------------------------------------------------------


def main():

  # 0 - neutral
  # 1 - route request
  # 2 - rejoin response
  # 3 - link status
  # 4 - network update
  # 5 - route reply
  # 6 - network report
  # 7 - end device timeout request
  # 8 - end device timeout response
  parse()
  

if __name__ == "__main__":
  main()
