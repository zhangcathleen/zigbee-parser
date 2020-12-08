#!/usr/bin/python3

import csv
import sys
import pyshark
#from scapy.all import *
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
  #leave_packets = {}

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

  csv_file = "results.csv"

  if no >= 2:
    path = sys.argv[1]
    shark_cap = pyshark.FileCapture(path)

#   if no == 3:
#     csv_file == sys.argv[2]
#   with open(csv_file, mode = 'w') as results_file:
#     results_writer = csv.writer(results_file, delimiter = ',')
#     csv_time = ''
#     csv_src = ''
#     csv_dst = ''
#     csv_len = ''
#     csv_protocol = ''
#     csv_frame_num = ''
#     csv_packet = ''
      
    try:
      for pk in shark_cap:
        frame = pk.frame_info
#        csv_time = frame.time
#        csv_len = frame.len
#        csv_protocol = frame.protocols
#        csv_frame_num = frame.number
        wpan = pk.wpan
        
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # ~~~~~~~ WPAN.CMD == 0x04 ~~~~~~~~~~~~~~
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # doesn't have cmd field, so
        # frame type === 0x03
        # frame len == 12

        # ==== data requests ===================
        # src : zed if src == 16 bit

        try:
          if wpan.frame_type == '0x00000003':
            if wpan.src_addr_mode == '0x00000002':
              zbee_ed.add(wpan.src16)
        except AttributeError:
          pass
        
        try:
          if 'zbee_nwk' in dir(pk):
            zbee = pk.zbee_nwk
            csv_src = wpan.src16
            csv_dst = wpan.dst16
          

                
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            # ~~~~~~ FRAME_TYPE == 0x01 ~~~~~~~~~
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            if zbee.frame_type == '0x00000001':
              
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~~ ZBEE.RADIUS == 1 ~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              if zbee.radius == '1':
                
                #  ===== link status packets ============
                #  Dst : 0xfffc
                #  Src : zc, zr 

                if zbee.dst == '0x0000fffc':
                  link_status = link_status + 1
                  #csv_packet = 'link status'
                  
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
                  #csv_packet = 'rejoin response'
                  
                  # for the leave packet
                  # if true : not a leave packet
#                  if (int(frame.number) > 12591):
#                    print(f'{frame.number} : {leave_pak}')
                  if leave_pak:
                    delete = []
                    for time, ip in leave_pak.items():
                      l_dst = ip[1]
                      l_src = ip[0]
                      if (zbee.src == l_dst):
                        if (zbee.dst == l_src):
#                          if (float(frame.time_epoch) - float(time) <= 60): # not a leave packet a rejoin request packet
                          delete.append(time)
#                            print(frame.time_epoch)
#                          elif (float(frame.time_epoch) - float(time) > 60): # a leave packet
#                            print('leave_3:')
                            #leave_3 = leave_3 + 1
#                            print(f'time {time} : [{zbee.dst} = {zbee.src}]')
#                            pass
                            # unsure how to put this in csv
                            #leave_packets[time] = ip
#                            delete.append(time)
                    for t in delete:
                      del leave_pak[t]
  
  
                  # for the rejoin request packets
                  # if true : a rejoin request packet
                  if rejoin_request_pak:
                    delete = []
                    for time, ip in rejoin_request_pak.items():
                      if (zbee.src == ip[1]):
                        if (zbee.dst == ip[0]):
                          #print(f'post leave {rejoin_request_pak}')
#                          if (float(frame.time_epoch) - float(time) <= 60): # a rejoin request!
                          rejoin_request = rejoin_request + 1
                            # unsure how to put this (prev packet) in csv
                          delete.append(time)
                          print(f'time {time} : {zbee.dst}, {zbee.src}')
#                          elif (float(frame.time_epoch) - float(time) > 60): # not a rejoin request
#                            delete.append(time)
                    for t in delete:
                      del rejoin_request_pak[t]
  
                  if zbee.src != '0x00000000':
                    zbee_r.add(zbee.src)
                  elif zbee.src == '0x00000000':
                    zbee_c.add(zbee.src64)
                    if zbee.src_route == True:
                      zbee_r.add(zbee.dst)
                    elif zbee.src_route == False:
                      zbee_ed.add(zbee.dst)
                
                   


                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                # ~~~~~~~~ DATA.LEN == 2 ~~~~~~~~~~~~~~~
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                if zbee.data_len == '2':
                  
                  # ===== leave packets ===========
                  # dst : zc, zr, zed, 0xfffd
                  # src : zc, zr, zed


                  if (zbee.dst == '0x0000fffd') or (zbee.dst in zbee_ed): # 1
                    leave_1 = leave_1 + 1
#                    print(f'{frame.number} : [{zbee.src} = {zbee.dst}]')
                    continue
                     
                  if (zbee.dst != '0x0000fffc'):
                    if (zbee.src == '0x00000000'): # 2
                      leave_2 = leave_2 + 1
#                      print(f'{frame.number} : [{zbee.src} = {zbee.dst}]')
                      continue
                       
                    else: # 3
                      leave_pak[frame.time_epoch] = (zbee.src, zbee.dst)
#                      print(f'check {frame.number} : {frame.time_epoch}')
                       
#                  if (zbee.dst != '0x0000fffc') and (zbee.dst != '0x0000ffff') and (zbee.dst != '0x00000000'): # 1 ZED
#                    if zbee.dst in zbee_ed:
#                      leave_1 = leave_1 + 1
#                      print(f'zbee.dst in zbee_ed : {frame.number} : [{zbee.src} = {zbee.dst}]')
#                      continue

#                    leave_zed[zbee.dst] = zbee.dst64
                    #csv_packet = 'leave packet check zed'
                     
                

                  # ===== rejoin request packets =======
                  # dst : zc, zr
                  # src : zr, zed
                  if (zbee.src != '0x00000000') and (zbee.dst != '0x0000fffc') and (zbee.dst != '0x0000fffd') and (zbee.dst != '0x0000ffff'):
                    rejoin_request_pak[f'{frame.time_epoch}'] = (f'{zbee.src}', f'{zbee.dst}') # has potential ZED
                    print(f'check {frame.number} : {frame.time_epoch}')
                     

  
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~~~ DATA.LEN == 13 ~~~~~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

              # ===== network update packets ===========
              # dst : 0xfffc
              # src : zc

              if zbee.data_len == '13':
                network_update = network_update + 1
                #csv_packet = 'network update packet'
                
                zbee_c.add(zbee.src64)
                 
              
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~ DATA.LEN == 3 ~~~~~~~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

              # ===== end device timeout request =======
              # request dst : zc, zr
              # request src : zed

              if (zbee.data_len == '3') and ((zbee.dst == '0x00000000') or (zbee.dst in zbee_r)) and (zbee.src in zbee_ed):
                edt_request = edt_request + 1
#                print(f'{frame.number} : [{zbee.src} = {zbee.dst}]')
  
                zbee_ed.add(zbee.src)
                if zbee.src64:
                  network_mac[f'zbee.src'] = f'zbee.src64'
  
                if zbee.dst != '0x00000000':
                  zbee_r.add(zbee.dst)
                elif zbee.dst == '0x00000000':
                  if zbee.dst64:
                    zbee_c.add(zbee.dst64)
                
                continue
                
                 

  
              # ===== end device timeout response =======
              # dst : zed
              # src : zc, zr

              if (zbee.data_len == '3') and ((zbee.src == '0x00000000') or (zbee.src in zbee_r)):
                edt_response = edt_response + 1
  
                zbee_ed.add(zbee.dst)
                if zbee.dst64:
                  network_mac[f'zbee.dst'] = f'zbee.dst64'
  
                if zbee.src != '0x00000000':
                  zbee_r.add(zbee.src)
                elif zbee.dst == '0x00000000':
                  if zbee.src64:
                    zbee_c.add(zbee.src64)
                
                continue
                 


              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~~~ ZBEE. RADIUS != 1 ~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              if zbee.radius != '1':
                    
                # ===== route reply packets ==========
                # Destination = ZC || ZR
                # Source = ZC || ZR

                if (wpan.src16 == zbee.src) and (zbee.ext_dst == '1') and ((zbee.data_len == '8') or (zbee.data_len == '16') or (zbee.data_len == '24')):
                  route_reply = route_reply + 1
                  #csv_packet = 'route reply packet'
                  
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
                  #csv_packet = 'network report packet'
                  
                  zbee_r.add(zbee.src)
                  zbee_c.add(zbee.dst64)
                  
                   

                  
                # ===== route request packets =========
                # dest : 0xfffc
                # src : zc, zr, zed

                if zbee.dst == '0x0000fffc':
                  route_request = route_request + 1
                  #csv_packet = 'route request packet'
                  
                  if zbee.src == '0x00000000':
                    zbee_c.add(zbee.src64)
                  #else:
                    #zbee_red.add(zbee.src)

                   
                

                # ===== network status packets ========
                # dst : zc, zr, zed, 0xfffd
                # src : zc, zr, zed
                    
                if zbee.data_len == '4':
                  if wpan.src64 == zbee.src64:
                    network_status = network_status + 1
                    #csv_packet = 'network status packet'
                    
                    if zbee.src != '0x00000000':
                      #zbee_red.add(zbee.src)
                      #if zbee.dst != '0x0000fffd':
                        #if zbee.dst != '0x00000000':
                          #zbee_red.add(zbee.dst)
                      if zbee.dst == '0x00000000':
                        zbee_c.add(zbee.dst64)

                    elif zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                      if zbee.dst != '0x0000fffd':
                        if zbee.src_route == True:
                          zbee_r.add(zbee.dst)
                        elif zbee.src_route == False:
                          zbee_ed.add(zbee.dst)
                        
                    continue                       
                    
                  if wpan.src64 == last_da:
                    network_status = network_status + 1
                    #csv_packet = 'network status packet'
  
                    if zbee.src != '0x00000000':
                     # zbee_red.add(zbee.src)
                      #if zbee.dst != '0x0000fffd':
                      #  if zbee.dst != '0x00000000':
                      #    zbee_red.add(zbee.dst)
                      if zbee.dst == '0x00000000':
                        zbee_c.add(zbee.dst64)

                    elif zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                      if zbee.dst != '0x0000fffd':
                        if zbee.src_route == True:
                          zbee_r.add(zbee.dst)
                        elif zbee.src_route == False:
                          zbee_ed.add(zbee.dst)
                    
                    continue
   
                if (zbee.data_len == '2') and (wpan.src64 != zbee.src64):
                  network_status = network_status + 1
                  #csv_packet = 'network status packet'
  
                  if zbee.src != '0x00000000':
                    #zbee_red.add(zbee.src)
                    #if zbee.dst != '0x0000fffd':
                      #if zbee.dst != '0x00000000':
                       # zbee_red.add(zbee.dst)
                    if zbee.dst == '0x00000000':
                      zbee_c.add(zbee.dst64)

                  elif zbee.src == '0x00000000':
                    zbee_c.add(zbee.src64)
                    if zbee.dst != '0x0000fffd':
                      if zbee.src_route == True:
                        zbee_r.add(zbee.dst)
                      elif zbee.src_route == False:
                        zbee_ed.add(zbee.dst)

                  continue      
 
  
                if (zbee.data_len == '2') or (zbee.data_len == '4'):
                  if zbee.dst == '0x0000fffd':
                    network_status = network_status + 1
                    #csv_packet = 'network status packet'
  
                    if zbee.src != '0x00000000':
                      #zbee_red.add(zbee.src)
                      #if zbee.dst != '0x0000fffd':
                        #if zbee.dst != '0x00000000':
                         # zbee_red.add(zbee.dst)
                      if zbee.dst == '0x00000000':
                        zbee_c.add(zbee.dst64)

                    elif zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                      if zbee.dst != '0x0000fffd':
                        if zbee.src_route == True:
                          zbee_r.add(zbee.dst)
                        elif zbee.src_route == False:
                          zbee_ed.add(zbee.dst)

                    continue      
 
  
                  elif zbee.dst in zbee_ed:
                    network_status = network_status + 1
                    #csv_packet = 'network status packet'
  
                    if zbee.src != '0x00000000':
                      #zbee_red.add(zbee.src)
                      #if zbee.dst != '0x0000fffd':
                       # if zbee.dst != '0x00000000':
                       #   zbee_red.add(zbee.dst)
                      if zbee.dst == '0x00000000':
                        zbee_c.add(zbee.dst64)

                    elif zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                      if zbee.dst != '0x0000fffd':
                        if zbee.src_route == True:
                          zbee_r.add(zbee.dst)
                        elif zbee.src_route == False:
                          zbee_ed.add(zbee.dst)

                    continue      
  
                  else:
                    ns_pak[frame.number] = zbee.dst
                    #csv_packet = 'network status packet check zed'


                # ===== route record packets ===========
                # dst : zc, zr
                # src : zc, zr, zed

                if zbee.dst != '0x0000fffc':
                  if (zbee.data_len == '6') or (zbee.data_len == '10'):
                    route_record = route_record + 1
                    #csv_packet = 'route record packet'
                    
                    #if zbee.src != '0x00000000':
                    #  zbee_red.add(zbee.src)
                    if zbee.src == '0x00000000':
                      zbee_c.add(zbee.src64)
                    
                    if zbee.dst != '0x00000000':
                      zbee_r.add(zbee.dst)
                    elif zbee.dst == '0x00000000':
                      zbee_c.add(zbee.dst64)

                     
                  
                  if zbee.ext_dst == '1':
                    if (zbee.data_len != '2') and (zbee.data_len != '4') and (wpan.src64 != zbee.src64):
                      route_record = route_record + 1
                      #csv_packet = 'route record packet'
                      
                     # if zbee.src != '0x00000000':
                      #  zbee_red.add(zbee.src)
                      if zbee.src == '0x00000000':
                        zbee_c.add(zbee.src64)
                      
                      if zbee.dst != '0x00000000':
                        zbee_r.add(zbee.dst)
                      elif zbee.dst == '0x00000000':
                        zbee_c.add(zbee.dst64)

                       
                    
                    if (zbee.dst != '0x0000fffd') and (wpan.src64 == zbee.src64) and (zbee.data_len == '2'):
                      route_record = route_record + 1
                      #csv_packet = 'route record packet'
                      
                      #if zbee.src != '0x00000000':
                      #  zbee_red.add(zbee.src)
                      if zbee.src == '0x00000000':
                        zbee_c.add(zbee.src64)
                      
                      if zbee.dst != '0x00000000':
                        zbee_r.add(zbee.dst)
                      elif zbee.dst == '0x00000000':
                        zbee_c.add(zbee.dst64)

                       
  
                  if zbee.data_len == '4':
                    if wpan.src64 == last_da:
                      route_record = route_record + 1
                      #csv_packet = 'route record packet'
                      
                      #if zbee.src != '0x00000000':
                      #  zbee_red.add(zbee.src)
                      if zbee.src == '0x00000000':
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
            if (wpan.frame_type == '0x00000001'):
              if (zbee.frame_type == '0x00000000') and (zbee.data_len == '20') and (zbee.dst == '0x0000fffd'):
                last_da = wpan.src64

            
            
          #results_writer.writerow([f'{csv_time}', f'{csv_src}', f'{csv_dst}', f'{csv_len}', f'{csv_protocol}', f'{csv_frame_num}', f'{csv_packet}'])
        except AttributeError:
          pass

    except KeyboardInterrupt:
      print("\n\nINTERRRUPPTEDDDD")
    

#    zbee_ed = zbee_red.difference(zbee_r)
 
    # check if the network status dst is end device
    for nid in ns_pak:
      if nid in zbee_ed:
        network_status = network_status + 1

    # checking if the leave dst is an end device 
    # if yes:
    #   add 1 to leave
    #   add to network_mac[network id] = mac
    for nid, mac in leave_zed.items():
      if nid in zbee_ed:
        leave_1 = leave_1 + 1
        network_mac[nid] = mac

    # check leave_pakckets
    print(leave_pak)
    leave_3 = leave_3 + len(leave_pak)

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
#    print(f'network_id : [mac]\n{network_mac}')
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
    print(f'mac : [network_id]\n{mac_network}')
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
