#!/usr/bin/python3

import csv
import sys
import pyshark
from scapy.all import *
import time


# TODO : progress bar instead of printing out all of the frame numbers
#       instead, print the results into a file
#       file will only be a thing if the entire thing finishes? Or maybe I should be able to let it go until it parses through
# TODO : end device timeout response
# TODO : end device timeour response


# start ------------------------------------------------------------------------


start_time = 0
'''   
  Sets the start_time to the clock
'''
def start():
  global start_time
  start_time = time.clock()

# finish ------------------------------------------------------------------------


'''
  Ouputs the time elapsed
'''
def finish():
  #print(start_time)
  print(f"\n\n========\ntime it took to run this command: {(time.clock() - start_time)/60} min\n========\n")

# parse ------------------------------------------------------------------------


'''
  parses through the entire pcap file
  returns number of packets for each type
  does device mapping
'''
def parse():
  start()
  no = len(sys.argv)
  
  # zigbee routers - stored as 16 bit
  zbee_r = set()
  
  # zigbee coorindators - stored as 64bit
  zbee_c = set()
  
  # zigbee end devices - stored as 16bit
  zbee_ed = set()
  
  # the ones that can't be distinguished between zigbee router + end devices
  zbee_red = set()
  
  # frames that might network status packets, but need the ZED
  ns_pak = {}
  
  # frames that might be rejoin request packets, but need the ZED
  rr_pak = list()
  
  # frames that might be end device timeout request or response packets,
  # but needs difference between ZED + ZR
  # dictionary - src : dst
  edt_pak = {}

  # most recent device announcement - wpan MAC
  last_da = ""
  
  link_status = 0
  network_update = 0
  route_reply = 0
  network_report = 0
  rejoin_response = 0
  route_request = 0
  network_status = 0
  route_record = 0
  edt_request = 0
  edt_response = 0
  leave = 0
  rejoin_request = 0
#  global zbee_r
#  global zbee_c
#  global zbee_ed
#  global zbee_red
#  global ns_pak
#  global rr_pak
#  global edt_pak
#
#  global link_status
#  global network_update
#  global route_reply
#  global network_report
#  global rejoin_response
#  global route_request
#  global network_status
#  global route_record
#  global edt_request
#  global edt_response

  if no >= 2:
    path = sys.argv[1]
    shark_cap = pyshark.FileCapture(path)
    try:
      for pk in shark_cap:
        frame = pk.frame_info
#       if int(frame.number) % 1000 == 0:
#         print(f"{frame.number}\n\n ")
#       else:
#         print(f"{frame.number} ", end="")
        try:
          if 'zbee_nwk' in dir(pk):
            zbee = pk.zbee_nwk
            wpan = pk.wpan
            
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            # ~~~~~~ FRAME_TYPE == 0x01 ~~~~~~~~~
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            if zbee.frame_type == '0x00000001':
#              if frame.number == '259':
#                print(f'259 {type(zbee.data_len)}')
#                print(3 == zbee.data_len)
#                print('3' == zbee.data_len)
              
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~~ ZBEE.RADIUS == 1 ~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              if zbee.radius == '1':
                
                #  ===== link status packets ============
                #  Dst : 0xfffc
                #  Src : zig_coordinator + zig_router
                if zbee.dst == '0x0000fffc':
                  link_status = link_status + 1
                  
                  if zbee.src != '0x00000000':
                    zbee_r.add(zbee.src)
                  else:
                    zbee_c.add(zbee.src64)
                 
                # ====== rejoin response packets =======
                # dst : zr, zed
                # src : zc, zr
                if zbee.data_len == '4':
                  rejoin_response = rejoin_response + 1
                  
                  if zbee.src != '0x00000000':
                    zbee_r.add(zbee.src)
                  else:
                    zbee_c.add(zbee.src64)
                  zbee_red.add(zbee.dst)
                
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                # ~~~~~~~~ DATA.LEN == 2 ~~~~~~~~~~~~~~~
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                if zbee.data_len == '2':
                  
                  # ===== rejoin request packets =======
                  # dst : zc + zr
                  # src : zr + zed
                  if (zbee.dst != '0x0000fffc') and (zbee.dst != '0x0000fffd') and (zbee.dst != '0x0000ffff') and (zbee.src != '0x00000000'):
                    rr_pak.add()
                
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~~~ DATA.LEN == 13 ~~~~~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ===== network update packets ===========
              # dst : 0xfffc
              # src : zc
              if zbee.data_len == '13':
                network_update = network_update + 1
                
                zbee_c.add(zbee.src64)
              
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~ DATA.LEN == 3 ~~~~~~~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ===== end device timeout request or response =======
              # request dst : zc, zr
              # request src : zed
              # response dst : zed
              # response : zc, zr
              if ('3' == zbee.data_len):
#                print(f'{zbee.src} {zbee.dst}')
                edt_pak[zbee.src] = zbee.dst
              
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~~~ ZBEE. RADIUS != 1 ~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              if zbee.radius != '1':
                    
                # ===== route reply packets ==========
                # Destination = ZC || ZR
                # Source = ZC || ZR
                if (wpan.src16 == zbee.src) and (zbee.ext_dst == '1') and ((zbee.data_len == '8') or (zbee.data_len == '16') or (zbee.data_len == '24')):
                  route_reply = route_reply + 1
                  
                  if zbee.src != '0x00000000':
                    zbee_r.add(zbee.src)
                  else:
                    zbee_c.add(zbee.src64)
                  
                  if zbee.dst != '0x00000000':
                    zbee_r.add(zbee.dst)
                  else:
                    zbee_c.add(zbee.dst64)
                 
                # ====== network report packets ========
                # destination : zc = 0x0000
                # source : zr 
                if (zbee.ext_dst == '0') and (zbee.dst == '0x00000000'):
                  network_report = network_report + 1
                  
                  zbee_r.add(zbee.src)
                  zbee_c.add(zbee.dst64)
                  
                # ===== route request packets =========
                # dest : 0xfffc
                # src : zc, zr, zed
                if zbee.dst == '0x0000fffc':
                  route_request = route_request + 1
                  
                  if zbee.src == '0x00000000':
                    zbee_c.add(zbee.src64)
                  else:
                    zbee_red.add(zbee.src)
                
                # ===== network status packets ========
                # dst : zc, zr, zed, 0xfffd
                # src : zc, zr, zed
                if zbee.data_len == '4':
                  if wpan.src64 == zbee.src64:
                    network_status = network_status + 1
                    
                    if zbee.src != '0x00000000':
                      zbee_red.add(zbee.src)
                    elif zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                    
                    if zbee.dst != '0x0000fffd':
                      if zbee.dst != '0x00000000':
                        zbee_red.add(zbee.dst)
                    elif zbee.dst == '0x00000000':
                      zbee_c.add(zbee.dst64)
                    
                  if wpan.src64 == last_da:
                    network_status = network_status + 1

                    if zbee.src != '0x00000000':
                      zbee_red.add(zbee.src)
                    elif zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                    
                    if zbee.dst != '0x0000fffd':
                      if zbee.dst != '0x00000000':
                        zbee_red.add(zbee.dst)
                    elif zbee.dst == '0x00000000':
                      zbee_c.add(zbee.dst64)
 
                if (zbee.data_len == '2') and (wpan.src64 != zbee.src64):
                  network_status = network_status + 1

                  if zbee.src != '0x00000000':
                    zbee_red.add(zbee.src)
                  elif zbee.src == '0x00000000':
                    zbee_c.add(zbee.src64)
                  
                  if zbee.dst != '0x0000fffd':
                    if zbee.dst != '0x00000000':
                      zbee_red.add(zbee.dst)
                  elif zbee.dst == '0x00000000':
                    zbee_c.add(zbee.dst64)
                
                if (zbee.data_len == '2') or (zbee.data_len == '4'):
#                  print(f'{zbee.dst}')
#                  print(f'network status len 2 or 4 {zbee.dst}')
                  if zbee.dst == '0x0000fffd':
#                    print(f'network status zbee.dst 0xfffd')
                    network_status = network_status + 1

                    if zbee.src != '0x00000000':
                      zbee_red.add(zbee.src)
                    elif zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                    
                    if zbee.dst != '0x0000fffd':
                      if zbee.dst != '0x00000000':
                        zbee_red.add(zbee.dst)
                    elif zbee.dst == '0x00000000':
                      zbee_c.add(zbee.dst64)

                  else:
#                    print(f"{frame.number} : {zbee.dst}")
#                    print(f'network status zbee.dst zed {zbee.dst64}')
                    ns_pak[frame.number] = zbee.dst64
                
                if (zbee.data_len == '4'):
#                  print(f'network status wpan mac last_da : {last_da} || wpan.src64 : {wpan.src64}')
                  if last_da != '':
                    if wpan.src64 == last_da:
                      network_status = network_status + 1
#                      print('network status wpan mac YES')

                # ===== route record packets ===========
                # dst : zc, zr
                # src : zc, zr, zed
                if zbee.dst != '0x0000fffc':
                  if (zbee.data_len == '6') or (zbee.data_len == '10'):
                    route_record = route_record + 1
                    
                    if zbee.src != '0x00000000':
                      zbee_red.add(zbee.src)
                    elif zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                    
                    if zbee.dst != '0x00000000':
                      zbee_r.add(zbee.dst)
                    elif zbee.dst == '0x00000000':
                      zbee_c.add(zbee.dst64)
                  
                  if zbee.ext_dst == '1':
                    if (zbee.dst != '0x0000fffc') and (zbee.data_len != '2') and (zbee.data_len != '4') and (wpan.src64 != zbee.src64):
                      route_record = route_record + 1
                      
                      if zbee.src != '0x00000000':
                        zbee_red.add(zbee.src)
                      elif zbee.src == '0x00000000':
                        zbee_c.add(zbee.src64)
                      
                      if zbee.dst != '0x00000000':
                        zbee_r.add(zbee.dst)
                      elif zbee.dst == '0x00000000':
                        zbee_c.add(zbee.dst64)
                    
                    if (zbee.dst != '0x0000fffc') and (zbee.dst != '0x0000fffd') and (zbee.ext_dst == '1') and (wpan.src64 == zbee.src64) and (zbee.data_len == '2'):
                      route_record = route_record + 1
                      
                      if zbee.src != '0x00000000':
                        zbee_red.add(zbee.src)
                      elif zbee.src == '0x00000000':
                        zbee_c.add(zbee.src64)
                      
                      if zbee.dst != '0x00000000':
                        zbee_r.add(zbee.dst)
                      elif zbee.dst == '0x00000000':
                        zbee_c.add(zbee.dst64)

                  if zbee.data_len == '4':
                    if last_da != '':
                      if wpan.src64 == last_da:
                        route_record = route_record + 1
                        
                        if zbee.src != '0x00000000':
                          zbee_red.add(zbee.src)
                        elif zbee.src == '0x00000000':
                          zbee_c.add(zbee.src64)
                        
                        if zbee.dst != '0x00000000':
                          zbee_r.add(zbee.dst)
                        elif zbee.dst == '0x00000000':
                          zbee_c.add(zbee.dst64)
            
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            # ~~~~~~~ WPAN.FRAME_TYPE == 0x01 ~~~~~~~
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          
            # ===== device announcements ============
            # dst : 0xfffd
            if (wpan.frame_type == '0x00000001') and (zbee.frame_type == '0x00000000') and (zbee.data_len == '20') and (zbee.dst == '0x0000fffd'):
              last_da = wpan.src64
            
        except AttributeError:
          pass
      

      # last requirement of network status
    except KeyboardInterrupt:
      print("\n\nINTERRRUPPTEDDDD")

    zbee_ed = zbee_red.difference(zbee_r)
 
    print('edt')   
    print(edt_pak)
    # separating between edt request + response
    for src, dst in edt_pak.items():
#      print(f'{src} {dst}')
      if (dst == '0x00000000') or (dst in zbee_r):
        print(f'edt dst {dst}')
        edt_request = edt_request + 1
      elif (src == '0x00000000') or (src in zbee_r):
        print(f'edt src {src}')
        edt_response = edt_response + 1
      


    # I DONT KNOWWWWWW
#    print (f"\n\nlast network status\n\n{ns_pak}\n{zbee_ed}")
    for pkt in ns_pak:
#      print(f"packet destination : {pkt}")
      if pkt in zbee_ed:
        network_status = network_status + 1
    finish()
    print(f"\n========\nzbee router addresses : {zbee_r}\n========\n")
    print(f"\n========\nzbee coordinator addresses : {zbee_c}\n========\n")
    print(f"\n========\nzbee end devices addresses : {zbee_ed}\n========\n")
    print(f"number of rejoin response packets : {rejoin_response}")
    print(f"number of network report packets : {network_report}")
    print(f"number of route reply packets : {route_reply}")
    print(f"number of network update packets : {network_update}")
    print(f"number of link status packets : {link_status}")
    print(f"number of route request packets : {route_request}")
    print(f"number of network status packets : {network_status}")
    print(f"number of route record packets : {route_record}")
    print(f"number of end device timeout request packets : {edt_request}")
    print(f"number of end device timeout response packets : {edt_response}")
    print(f"number of leave packets : {leave}")
    print(f"number of rejoin request packets : {rejoin_request}")
  else:
    print("please give me a file")
    sys.exit()  

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
