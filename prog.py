#!/usr/bin/python3

import csv
import sys
import pyshark
from scapy.all import *
import time


# TODO : progress bar instead of printing out all of the frame numbers
#       instead, print the results into a file
#       file will only be a thing if the entire thing finishes? Or maybe I should be able to let it go until it parses through
# TODO : a set for zbee coorindators addr64
# TODO : an all in 1 testing everything
# TODO : end device timeout response
# TODO : end device timeour response
# TODO : print_zrg

# network_report + link_status + route_reply
zbee_r = {"hi"}
start_time = 0

# more_parse ------------------------------------------------------------------------


"""
  Parses the next command/packet based on user input
"""
def more_parse():

  doc = '\n\n  OPTIONS:\n         routeRequest\n         rejoinResponse\n         linkStatus\n         networkUpdate\n         routeReply\n         networkReport\n         endDeviceTimeoutRequest [edtRequest]\n         endDeviceTimeoutResponse [edtResponse]\n\n         zrg     -print out the addr of routers + coord \n\n  STOP:\n       Ctrl + C\n\n   QUIT:\n      use quit to exit\n\n'

  while True:
    try:
      option = input(doc)
      while True:
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
        elif (option == 'zrg') or (option == 'ZRG') or (option == 'zRG') or (option == 'zrG') or (option == 'Zrg') or (option == 'ZRg') or (option == 'ZrG'):
          return print_zrg()
        elif (option == 'quit'):
          sys.exit("\n\nexiting program\nbye!\n")
        else:
          option = input(doc)
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


# count_rejoin_response ------------------------------------------------------------------------
#TODO: get the destination + source


"""
  Counts the number of rejoin response packets in the pcap file
"""
def count_rejoin_response():
  print("\nanalyzing for rejoin response packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  """
    count should represent how many packets of that type are
  """
  count = 0 
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
    except AttributeError:
      pass
  print('total count ' + str(count))


# count_route_request ------------------------------------------------------------------------
#TODO: get the destination + source

"""
  Counts the number of route request packets in the pcap file
"""
def count_route_request():
  print("\nanalyzing for route request packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  """
    count should represent how many packets of that type are
  """
  count = 0 
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
    except AttributeError:
      pass
  print('total count ' + str(count))

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
  """
    Try because you could get attribute error - a packet w/no zbee layer
  """
  try:
    # `for` needs to be inside of `try` because exception `bubbles` up to `try`
    # but if `try` is inside of `for` loop, it will be consumed
    for pk in shark_cap:
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
            zbee_r.add(zbee.src)
  except KeyboardInterrupt:
    print("\n\nINTERRRUPPTEDDDD")
    print(f"number of link status packets up to the previous number: {count}")
    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
    print(zbee_r)
    finish()
    more_parse()
  except AttributeError:
    pass
  else:
    print(f"total number of link status packets : str(count)")
    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
    print(zbee_r)
    finish()
    more_parse()

# count_network_update ------------------------------------------------------------------------
#TODO: get the destination + source

"""
  Counts the number of network update packets in the pcacp file
"""
def count_network_update():
  print("\nanalyzing for network update packets\n")
  path = 'Zigator_all.pcap'
  shark_cap = pyshark.FileCapture(path)
  """
    count should represent how many packets of that type are
  """
  count = 0 
  for pk in shark_cap:
    """
      Try because you could get attribute error - a packet w/no zbee layer
    """
    try:
        zbee = pk.zbee_nwk
        if (zbee.frame_type == '0x00000001') and (zbee.data_len == '13'):
           """
             Printing the frame number -> cross reference w/ Wireshark what the packet is
           """
           frame = pk.frame_info
           print(frame.number)
           count = count + 1
    except AttributeError:
      pass
  print('total count ' + str(count))

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
  """
    Try because you could get attribute error - a packet w/no zbee layer
  """
  try:
    """
      count should represent how many packets of that type are
    """
    count = 0 
    for pk in shark_cap:
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
          # not 0x0000 0000 because that's the zigbee coordinator (which should all be already identifiedaas 0x0000
           if zbee.src != '0x00000000':
             zbee_r.add(zbee.src)
  except KeyboardInterrupt:
    print("\n\nINTERRRUPPTEDDDD")
    print(f"number of route reply packets up to the previous one: {count}")
    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
    print(zbee_r)
    finish()
    more_parse()
  except AttributeError:
    pass
  else:
    print("total number of route reply packets {str(count)}")
    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
    print(zbee_r)
    finish()
    more_parse()

# count_network_report ------------------------------------------------------------------------
# TODO : add dict for zbee src + zbee64
# TODO : add set for zbee coord bc all zbee coord = 0x0000


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
  """
    Try because you could get attribute error - a packet w/no zbee layer
  """
  try:
    for pk in shark_cap:
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
          print(count)
          print(f"zbee.src : {zbee.src}")
          zbee_r.add(zbee.src)
  except KeyboardInterrupt:
    print("\n\nINTERRRUPPTEDDDD")
    print(f"number of network report packets up to the previous packet: {count}")
    print(f"zbee routers {len(zbee_r) - 1} : ", end = " ")
    print(zbee_r)
    finish()
    more_parse()
  except AttributeError:
    pass
  else:
    print(f"total number of network report packets {str(count)}")
    print(f"zbee routers [{len(zbee_r) - 1}] : ", end = " ")
    print(zbee_r)
    finish()
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
