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
  
  # frames that might be end device timeout request or response packets,
  # but needs difference between ZED + ZR
  # dictionary - src : dst
  edt_pak = {}

  # most recent device announcement - wpan MAC
  last_da = ""

  # mapping the network id w/ mac address
  # network id : mac address
  network_mac = {} 

  # mapping the time_epoch : (src, (dst, dst64)) of the rejoin request packet
  # need to check w the next rejoin response w/in 1 min :
  # if yes = rejoin request packet
  rejoin_request_pak = {}

  # frames that might be rejoin request pakcets, but need to not be zed
  # maps network_id : mac id
  rejoin_request_zed = {}
  
  # mapping the time_epoch and (src, dst) of the leave packet
  # to check w the next rejoin response w/in 1 min :
  # if not = leave packet
  leave_pak = {}

  # leave time : (src, dst) after identifying that they are leave packets
  # in rejoin response
  leave_packets = {}

  # frames that might be leave packets, but need the ZED
  # maps network_id : mac_id
  leave_zed = {}
  
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
  leave_1 = 0
  leave_2 = 0
  leave_3 = 0
  rejoin_request = 0
#  global zbee_r
#  global zbee_c
#  global zbee_ed
#  global zbee_red
#  global ns_pak
#  global rejoin_request_pak
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
#        print(frame.time)
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
                #  Src : zc, zr 
                if zbee.dst == '0x0000fffc':
                  link_status = link_status + 1
                  
                  if zbee.src != '0x00000000':
                    zbee_r.add(zbee.src)
                  elif zbee.src == '0x00000000':
                    zbee_c.add(zbee.src64)

                  if zbee.src64:
                    network_mac[f'{zbee.src}'] = f'{zbee.src64}'
                 
                # ====== rejoin response packets =======
                # dst : zr, zed
                # src : zc, zr
                if zbee.data_len == '4':
                  rejoin_response = rejoin_response + 1
                  
                  # for the leave packet
                  # if true : not a leave packet
                  if leave_pak:
                    for time, ip in leave_pak.items():
                      if (zbee.src == ip[1]):
                        if (zbee.dst == ip[0]):
                          if (float(frame.time_epoch) - float(time) <= 60): # not a leave packet
                            continue
                          elif (float(frame.time_epoch) - float(time) > 60): # a leave packet
#                            leave = leave + 1
                            leave_packets[time] = ip
                    leave_pak = {}
#                  print(f'leave_pak : {leave_pak}')


                  # for the rejoin request packets
                  # if true : a rejoin request packet
                  if rejoin_request_pak:
                    for time, ip in rejoin_request_pak.items():
                      if (zbee.src == ip[1]):
                        if (zbee.dst == ip[0]):
                          print(f'post leave {rejoin_request_pak}')
                          if (float(frame.time_epoch) - float(time) <= 60): # a rejoin request!
                            print('more rejoin requests?')
                            rejoin_request = rejoin_request + 1
#                            rejoin_request_zed[old_dst[0]] = old_dst[1]
                          elif (float(frame.time_epoch) - float(time) > 60): # not a rejoin request
                            continue
                    rejoin_request_pak = {}

                  if zbee.src != '0x00000000':
                    zbee_r.add(zbee.src)
                  else:
                    zbee_c.add(zbee.src64)
                  zbee_red.add(zbee.dst)
                
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                # ~~~~~~~~ DATA.LEN == 2 ~~~~~~~~~~~~~~~
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                if zbee.data_len == '2':
                  
                  # ===== leave packets ===========
                  # dst : zc, zr, zed, 0xfffd
                  # src : zc, zr, zed
#                  print(f'{zbee.dst}')
#                  print(frame.number)
#                  elif (int(frame.number) == 354):
#                    print(f'{zbee.data_len}')
                  if (zbee.dst == '0x0000fffd'): # #1
#                    if (frame.number == '354'):
#                      print(f'{zbee.dst}')
#                    print(f'leave_1 {frame.number}')
                    leave_1 = leave_1 + 1
                  elif (zbee.dst != '0x0000fffc'):
#                    if (frame.number == '354'):
#                      print(f'{zbee.dst}')
                    if (zbee.src == '0x00000000'): # #2
                      leave_2 = leave_2 + 1
                    else: # #3
                      leave_pak[frame.time_epoch] = (zbee.src, zbee.dst)
                  elif (zbee.dst != '0x0000fffc') and (zbee.dst != '0x0000ffff') and (zbee.dst != '0x00000000'): # #1 ZED
#                    print(zbee.dst)
#                    print(f'dst64 {zbee.dst64}')
                    leave_zed[zbee.dst] = zbee.dst64
                
                 # ===== rejoin request packets =======
                 # dst : zc, zr
                 # src : zr, zed
                  if (zbee.src != '0x00000000') and (zbee.dst != '0x0000fffc') and (zbee.dst != '0x0000fffd') and (zbee.dst != '0x0000ffff'):
#                     print(zbee.dst)
                     #print(zbee.dst64)
                     #dst = (zbee.dst, zbee.dst64)
                     #print(f'dst: {dst}\nrejion_request_pak : {rejoin_request_pak}')
                     #rejoin_request_pak[f'{frame.time_epoch}'] = {f'{zbee.src}' : dst} # has potential ZED
                     rejoin_request_pak[f'{frame.time_epoch}'] = (f'{zbee.src}', f'{zbee.dst}') # has potential ZED
#                     print(f'possible rejoin request? {rejoin_request_pak}')
#                    else: # zbee_nwk.dst != ZED
#                      rejoin_request_pak[frame.time_epoch] = (zbee.src, (zbee.dst, zbee.dst64))
#                      #rejoin_request_zed[zbee.dst] = zbee.dst64

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
              # ===== end device timeout request =======
              # request dst : zc, zr
              # request src : zed
              if (zbee.data_len == '3') and (zbee.dst == '0x00000000') and (zbee.dst in zbee_r):
#                print(f'{zbee.src} {zbee.dst}')
                edt_pak[zbee.src] = zbee.dst
                zbee_ed.add(zbee.src)
                print(f'request before {edt_request}')
                edt_request = edt_request + 1
                print(f'request after {edt_request}')
                
                if zbee.src64:
                  network_mac[f'zbee.src'] = f'zbee.src64'

              # ===== end device timeout response =======
              # response dst : zed
              # response : zc, zr
              if (zbee.data_len == '3') and (zbee.src == '0x00000000') and (zbee.src in zbee_r):
#                print(f'{zbee.src} {zbee.dst}')
                #edt_pak[zbee.src] = zbee.dst
                zbee_ed.add(zbee.dst)
                print(f'response before {edt_response}')
                edt_response = edt_response + 1
                print(f'response after {edt_response}')
              
                if zbee.dst64:
                  network_mac[f'zbee.dst'] = f'zbee.dst64'
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
                    # added for if zbee_nwk.dst == zed
                    ns_pak[frame.number] = zbee.dst
                
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
 
#    print('edt')   
#    print(edt_pak)
    # separating between edt request + response
    for src, dst in edt_pak.items():
#      print(f'{src} {dst}')
      if (dst == '0x00000000') or (dst in zbee_r):
#        print(f'edt dst {dst}')
        edt_request = edt_request + 1
      elif (src == '0x00000000') or (src in zbee_r):
#        print(f'edt src {src}')
        edt_response = edt_response + 1
      

#    print (f"\n\nlast network status\n\n{ns_pak}\n{zbee_ed}")
    for nid in ns_pak:
#      print(f"packet destination : {pkt}")
      if nid in zbee_ed:
        network_status = network_status + 1

    # checking if the leave dst is an end device 
    # if yes:
    #   add 1 to leave
    #   add to network_mac[network id] = mac
    print(leave_zed)
    for nid, mac in leave_zed.items():
      if nid in zbee_ed:
        print(nid)
        leave_1 = leave_1 + 1
        network_mac[nid] = mac

    # check leave_pak
    for time, addr in leave_pak.items():
      print(f'time: {time} :: src, dst: {addr}')
    leave_3 = leave_3 + len(leave_pak)
    print(f'leave_packet : {leave_packets}')

#    # check if the rejoin_request_zed is an end device
#    # if yes:
#    #   skip
#    # if no:
#    #   add 1 to rejoin request
#    #   add to network_mac[network id] = mac
#    for nid, mac in rejoin_request_zed.items():
#      if nid in zbee_ed:
#        continue
#      else:
#        rejoin_request = rejoin_request + 1
#        network_mac[nid] = mac





    # swapping network : mac -> mac : network
    print(f'network_id : [mac]\n{network_mac}')
    mac_network = {}
    for network, mac in network_mac.items():
      try:
        mac_network[mac].add(network)
      except KeyError:
        mac_network[mac] = {network}

    

#    print(leave_packets)
#    leave = leave + len(leave_packets)
#   c_zbee = {}
#   nm_copy = network_mac
#   for c in zbee_c:
#     print(nm_copy)
#     for nip, mac in nm_copy.items():
#       if mac == c:
#         try:
#           c_zbee[mac].add(nip)
#         except KeyError:
#           c_zbee[mac] = {nip}
#         network_mac.pop(nip)
# 

#   r_zbee = {}
#   nm_copy = network_mac
#   for r in zbee_r:
#     for nip, mac in nm_copy.items():
#       if nip == r:
#         try:
#           r_zbee[mac].add(nip)
#         except KeyError:
#           r_zbee[mac] = {nip}
#         network_mac.pop(nip)
#   

#   ed_zbee = {}
#   nm_copy = network_mac
#   for ed in zbee_ed:
#     for nip, mac in network_mac.items():
#       if nip == ed:
#         try:
#           ed_zbee[mac].add(nip)
#         except KeyError:
#           ed_zbee[mac] = {nip}
#         nm_copy.pop(nip)

#   print(len(nm_copy))
      
    
    
    finish()
#    print(f"\n========\nzbee router addresses : {zbee_r}\n========\n")
#    print(f"\n========\nzbee coordinator addresses : {zbee_c}\n========\n")
#    print(f"\n========\nzbee end devices addresses : {zbee_ed}\n========\n")
#    print(f'mac : [network_id]\n{mac_network}')
#   print(c_zbee)
#   print(r_zbee)
#   print(ed_zbee)

    print("\n\nzbee coordinator addresses:")
    for c in zbee_c:
      print(f"     {c}")

    print("\n\nzbee router addresses:")
    for r in zbee_r:
      print(f"     {r}")

    print("\n\nzbee end devices addresses:")
    for ed in zbee_ed:
      print(f"     {ed}")

    print("\n\n\n")
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
    print(f"number of leave packets : {leave_1} : {leave_2} : {leave_3}")
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
