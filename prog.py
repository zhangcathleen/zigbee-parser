#!/usr/bin/python3

import csv
import sys
import pyshark
from scapy.all import *
import time


# TODO: progress bar instead of printing out all of the frame numbers
#       instead, print the results into a file
#       file will only be a thing if the entire thing finishes? Or maybe I should be able to let it go until it parses through

zbee_rc = {"hi"}
start_time = 0

"""
  Parses the next command/packet based on user input
"""
def more_parse():

  eror = '\n\n  OPTIONS:\n       --routeRequest\n       --rejoinResponse\n       --linkStatus\n       --networkUpdate\n       --routeReply\n       --networkReport\n       --endDeviceTimeoutRequest [edtRequest]\n       --endDeviceTimeoutResponse [--edtResponse]\n\n'

  option = input(eror)
  try:
    while True:
      if (option == '--routeRequest') or (option == '--routerequest') or (option == '--RouteRequest') or (option == 'routeRequest') or (option == 'routerequest') or (option == 'RouteRequest'):
        print("\nanalyzing for route request packets\n")
        return count_route_request()
      elif (option == '--rejoinResponse') or (option == '--rejoinresponse') or (option == '--RejoinResponse') or (option == 'rejoinResponse') or (option == 'rejoinresponse') or (option == 'RejoinResponse'):
        print("\nanalyzing for rejoin response packets\n")
        return count_rejoin_response()
      elif (option == '--linkStatus') or (option == '--linkstatus') or (option == '--LinkStatus') or (option == 'linkStatus') or (option == 'linkstatus') or (option == 'LinkStatus'):
        print("\nanalyzing for link status packets\n")
        return count_link_status()
      elif (option == '--networkUpdate') or (option == '--networkupdate') or (option == '--NetworkUpdate') or (option == 'networkUpdate') or (option == 'networkupdate') or (option == 'NetworkUpdate'):
        print("\nanalyzing for network update packets\n")
        return count_network_update()
      elif (option == '--routeReply') or (option == '--routereply') or (option == '--RouteReply') or (option == 'routeReply') or (option == 'routereply') or (option == 'RouteReply'):
        print("\nanalyzing for route reply packets\n")
        return count_route_reply()
      elif (option == '--networkReport') or (option == '--networkreport') or (option == '--NetworkReport') or (option == 'networkReport') or (option == 'networkreport') or (option == 'NetworkReport'):
        print("\nanalyzing network report packets\n")
        return count_network_report()
      elif (option == '--endDeviceTimeoutRequest') or (option == '--enddevicetimeoutrequest') or (option == '--EndDeviceTimeoutRequest') or (option == 'edtrequest') or (option == '--edtRequest') or (option == 'endDeviceTimeoutRequest') or (option == 'enddevicetimeoutrequest') or (option == 'EndDeviceTimeoutRequest') or (option == 'edtRequest'):
        print("\nanalyzing end device timeout request packets\n")
        return 7
      elif (option == '--endDeviceTimeoutResponse') or (option == '--enddevicetimeoutresponse') or (option == '--EndDeviceTimeoutResponse') or (option == 'edtresponse') or (option == '--edtResponse') or (option == 'endDeviceTimeoutResponse') or (option == 'enddevicetimeoutresponse') or (option == 'EndDeviceTimeoutResponse') or (option == 'edtResponse'):
        print("\nanalyzing end device timeout response packets\n")
        return 8
      else:
        option = input(eror)
  except KeyboardInterrupt:
    sys.exit("\n\nexiting program\nbye!")

"""
  Parses through the command line arguments to determine which packet to count
"""
def parse():

  eror = '\n  usage: ./prog.py [OPTION]\n\n  OPTIONS:\n       --routeRequest\n       --rejoinResponse\n       --linkStatus\n       --networkUpdate\n       --routeReply\n       --networkReport\n       --endDeviceTimeoutRequest [edtRequest]\n       --endDeviceTimeoutResponse [--edtResponse]\n'
  no = len(sys.argv)

  if no == 2:
    option = sys.argv[1]
    if (option == '--routeRequest') or (option == '--routerequest') or (option == '--RouteRequest'):
      print("\nanalyzing for route request packets\n")
      return count_route_request()
    elif (option == '--rejoinResponse') or (option == '--rejoinresponse') or (option == '--RejoinResponse'):
      print("\nanalyzing for rejoin response packets\n")
      return count_rejoin_response()
    elif (option == '--linkStatus') or (option == '--linkstatus') or (option == '--LinkStatus'):
      print("\nanalyzing for link status packets\n")
      return count_link_status()
    elif (option == '--networkUpdate') or (option == '--networkupdate') or (option == '--NetworkUpdate'):
      print("\nanalyzing for network update packets\n")
      return count_network_update()
    elif (option == '--routeReply') or (option == '--routereply') or (option == '--RouteReply'):
      print("\nanalyzing for route reply packets\n")
      return count_route_reply()
    elif (option == '--networkReport') or (option == '--networkreport') or (option == '--NetworkReport'):
      print("\nanalyzing network report packets\n")
      return count_network_report()
    elif (option == '--endDeviceTimeoutRequest') or (option == '--enddevicetimeoutrequest') or (option == '--EndDeviceTimeoutRequest') or (option == 'edtrequest') or (option == '--edtRequest'):
      print("\nanalyzing end device timeout request packets\n")
      return 7
    elif (option == '--endDeviceTimeoutResponse') or (option == '--enddevicetimeoutresponse') or (option == '--EndDeviceTimeoutResponse') or (option == 'edtresponse') or (option == '--edtResponse'):
      print("\nanalyzing end device timeout response packets\n")
      return 8
    else:
      more_parse()
  else:
    more_parse()


"""
  Device-maps the devices
"""

"""
  Sets the start_time to the clock
"""
def start():
  global start_time
  start_time = time.clock()

"""
  Ouputs the time elapsed
"""
def finish():
  print(start_time)
  print(f"time it took to run this command: {(time.clock() - start_time)/60} min")

"""
  Counts the number of rejoin response packets in the pcap file
"""
def count_rejoin_response():
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
  print('final count ' + str(count))


"""
  Counts the number of route request packets in the pcap file
"""
def count_route_request():
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
  print('final count ' + str(count))


"""
  Counts the number of link status packets in the pcap file
"""
def count_link_status():
  start()
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
          if zbee.src != '0x00000000':
            print(zbee.src)
            zbee_rc.add(zbee.src)
  except KeyboardInterrupt:
    print("INTERRRUPPTEDDDD")
    print(f"Count up to the previous number: {count}")
    print(zbee_rc)
    finish()
    more_parse()
  except AttributeError:
    pass
  else:
    print('final count ' + str(count))
    print(zbee_rc)
    finish()
    more_parse()


"""
  Counts the number of network update packets in the pcacp file
"""
def count_network_update():
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
  print('final count ' + str(count))



"""
  Counts the number of route reply packets in the pcacp file
  Destination = ZC || ZR
  Source = ZC || ZR
"""
def count_route_reply():
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
        wpan = pk.wpan
        if (zbee.frame_type == '0x00000001') and (zbee.radius != '1') and (wpan.src16 == zbee.src) and (zbee.ext_dst == '1') and ((zbee.data_len == '8') or (zbee.data_len == '16') or (zbee.data_len == '24')):
           """
             Printing the frame number -> cross reference w/ Wireshark what the packet is
           """
           frame = pk.frame_info
           print(frame.number)
           count = count + 1
    except AttributeError:
      pass
  print('final count ' + str(count))



"""
  Counts the number of network report packets in the pcacp file
"""
def count_network_report():
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
        wpan = pk.wpan
        if (zbee.frame_type == '0x00000001') and (zbee.radius != '1') and (zbee.ext_dst == '0') and (zbee.dst == '0x00000000'):
           """
             Printing the frame number -> cross reference w/ Wireshark what the packet is
           """
           frame = pk.frame_info
           print(frame.number)
           count = count + 1
    except AttributeError:
      pass
  print('final count ' + str(count))

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
