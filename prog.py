#!/usr/bin/python3

import csv
import sys
import pyshark
from scapy.all import *
import time

"""
  Parses through the command line arguments to determine which packet to count
"""
def parse():

  eror = 'Usage: ./prog.py [OPTION]\n\n  --routeRequest\n  --rejoinResponse\n  --linkStatus\n  --networkUpdate\n  --routeReply\n --networkReport\n --endDeviceTimeoutRequest [edtRequest]\n  --endDeviceTimeoutResponse [--edtResponse]\n'
  no = len(sys.argv)

  if no == 1:
    sys.exit(eror)
  elif no == 2:
    option = sys.argv[1]
    if (option == '--routeRequest') or (option == '--routerequest') or (option == '--RouteRequest'):
      return count_route_request()
    elif (option == '--rejoinResponse') or (option == '--rejoinresponse') or (option == '--RejoinResponse'):
      return count_rejoin_response()
    elif (option == '--linkStatus') or (option == '--linkstatus') or (option == '--LinkStatus'):
      return count_link_status()
    elif (option == '--networkUpdate') or (option == '--networkupdate') or (option == '--NetworkUpdate'):
      print('network_update')
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
      sys.exit(eror)
  else:
    sys.exit(eror)
  

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
        if (zbee.frame_type == '0x00000001') and (zbee.radius == '1') and (zbee.dst == '0x0000fffc'):
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


"""
  Counts the number of packets of the pcap file
"""
def read_pcap(packet):
  path = 'Zigator_all.pcap'
  # Reading using scapy
  #shark_cap = rdpcap('Zigator_all.pcap')
  # Reading using pyshark
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
        #If the packet is a route request packet
        if packet == 1:
          if (zbee.frame_type == '0x00000001') and (zbee.radius != '1') and (zbee.dst == '0x0000fffc'):
            """
              Printing the frame number -> cross reference w/ Wireshark what the packet is
            """
            frame = pk.frame_info
            print(frame.number)
            count = count + 1
        # If the packet is a rejoin response packet
        elif (zbee.frame_type == '0x00000001') and (zbee.radius == '1') and (zbee.data_len == '4') and (packet == 2):
          """
            Printing the frame number -> cross reference w/ Wireshark what the packet is
          """
          frame = pk.frame_info
          print(frame.number)
          count = count + 1
        # If the packet is a link status packet
        elif packet == 3:
          if (zbee.frame_type == '0x00000001') and (zbee.radius == '1') and (zbee.dst == '0x0000fffc'):
             """
               Printing the frame number -> cross reference w/ Wireshark what the packet is
             """
             frame = pk.frame_info
             print(frame.number)
             count = count + 1
    except AttributeError:
#      print('pass')
      pass
  print('final count ' + str(count))

def main():

  start_time = time.clock()

  # 0 - neutral
  # 1 - route request
  # 2 - rejoin response
  # 3 - link status
  # 4 - network update
  # 5 - route reply
  # 6 - network report
  # 7 - end device timeout request
  # 8 - end device timeout response
  packet = parse()
  
  #count(packet)
#  read_pcap(packet)

  print(time.clock() - start_time)

if __name__ == "__main__":
  main()
