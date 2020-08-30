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
    if (option == '--routeRequest') | (option == '--routerequest') | (option == '--RouteRequest'):
      return count_route_request
    elif (option == '--rejoinResponse') | (option == '--rejoinresponse') | (option == '--RejoinResponse'):
      return count_rejoin_response()
    elif (option == '--linkStatus') | (option == '--linkstatus') | (option == '--LinkStatus'):
      return count_link_status()
    elif (option == '--networkUpdate') | (option == '--networkupdate') | (option == '--NetworkUpdate'):
      return 4
    elif (option == '--routeReply') | (option == '--routereply') | (option == '--RouteReply'):
      return 5
    elif (option == '--networkReport') | (option == '--networkreport') | (option == '--NetworkReport'):
      return 6
    elif (option == '--endDeviceTimeoutRequest') | (option == '--enddevicetimeoutrequest') | (option == '--EndDeviceTimeoutRequest') | (option == 'edtrequest') | (option == '--edtRequest'):
      return 7
    elif (option == '--endDeviceTimeoutResponse') | (option == '--enddevicetimeoutresponse') | (option == '--EndDeviceTimeoutResponse') | (option == 'edtresponse') | (option == '--edtResponse'):
      return 8
    else:
      sys.exit(eror)
  else:
    sys.exit(eror)
  
"""
  Counts the number of packets in the file for the given type (packet)
  Of a CSV file (limited version)
"""
def count(packet):

  path = 'test.csv'

  with open(path, 'r') as csvfile:
    f = csv.reader(csvfile, delimiter=',')
    count = 0
    for brak in f:
      # route request
      if (brak[0] == '0x00000001') & (brak[1] != '1') & (brak[2] == '0x0000fffc') & (packet == 1):
        count = count + 1
        print(brak)
      # rejoin response
      elif (brak[0] == '0x00000001') & (brak[1] == '1') & (brak[3] == '4') & (packet == 2):
        count = count + 1
        print(brak)
      # link status
      elif (brak[0] == '0x00000001') & (brak[1] == '1') & (brak[2] == '0x0000fffc') & (packet == 3):
        count = count + 1
        print(brak)
      # network update
      elif (brak[0] == '0x00000001') & (brak[3] == '13') & (packet == 4):
        count = count + 1
        print(brak)
      # route reply
      print(count)


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
        if (zbee.frame_type == '0x00000001') & (zbee.radius == '1') & (zbee.data_len == '4')
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
        if (zbee.frame_type == '0x00000001') & (zbee.radius != '1') & (zbee.dst == '0x0000fffc'):
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
        if (zbee.frame_type == '0x00000001') & (zbee.radius == '1') & (zbee.dst == '0x0000fffc'):
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
          if (zbee.frame_type == '0x00000001') & (zbee.radius != '1') & (zbee.dst == '0x0000fffc'):
            """
              Printing the frame number -> cross reference w/ Wireshark what the packet is
            """
            frame = pk.frame_info
            print(frame.number)
            count = count + 1
        # If the packet is a rejoin response packet
        elif (zbee.frame_type == '0x00000001') & (zbee.radius == '1') & (zbee.data_len == '4') & (packet == 2):
          """
            Printing the frame number -> cross reference w/ Wireshark what the packet is
          """
          frame = pk.frame_info
          print(frame.number)
          count = count + 1
        # If the packet is a link status packet
        elif packet == 3:
          if (zbee.frame_type == '0x00000001') & (zbee.radius == '1') & (zbee.dst == '0x0000fffc'):
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
