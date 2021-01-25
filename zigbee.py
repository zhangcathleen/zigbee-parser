#!/usr/bin/python3


# need to install pyshark + tshark
# pip install pyshark
# sudo apt install tshark


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
  start_time = time.process_time()

# finish ------------------------------------------------------------------------


'''
  Ouputs the time elapsed
'''
def finish():
  print(f"\n\n========\ntime it took to run this command: {(time.process_time() - start_time)/60} min\n========\n")

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
  
  # # the ones that can't be distinguished between zigbee router + end devices
  # zbee_red = set()
  
  # frames that might network status packets, but need the ZED
  # ns_pak = {}

  # # keeps track of the previous device announcement zbee src + wpan src/dst
  # # x = [zbee.src, wpan.dst]
  # # a list => d_announce.append(x)
  # d_announce = [0, 0]

  # keeps track of the device announcement + devices
  d_announce = []

  # keeps track of the previous packets for a -> b 0 (4)
  # helps identify network status & device announcement
  # true = network status
  # false = route record
  ab0 = None

  # keeps track of the previous packets for b -> a 0 (4)
  # helps identify between network status & device announcements
  # true = network status
  # false = route record
  ba0 = None

  # keeps track of the previous packet of either network status/route record
  # if it's the same packet, then it's the same type
  # previous = [zbee.src, zbee.dst, wpan.src16, wpan.dst16, data.len, type]
  # type : true = network status, false = route record
  previous = [0, 0, 0, 0, 0, None]

  # # keeps track of d_announce times (time : zbee src)
  # d_time = []

  # most recent route record (identified by device announcement) - WPAN SRC
  last_rr = ""

  # mapping the network id w/ mac address
  # network id : mac address
  network_mac = {} 

  # maps [time : (src, dst)]
  # identify between leave + rejoin request packets
  check_response = {}

#  # mapping the time_epoch : (src, (dst, dst64)) of the rejoin request packet
#  # need to check w the next rejoin response w/in 1 min :
#  # if yes = rejoin request packet
#  rejoin_request_pak = {}
#
#  # frames that might be rejoin request pakcets, but need to not be zed
#  # maps network_id : mac id
#  rejoin_request_zed = {}
  
#  # mapping the time_epoch and (src, dst) of the leave packet
#  # to check w the next rejoin response w/in 1 min :
#  # if not = leave packet
#  leave_pak = {}

  # leave time : (src, dst) 
  # helping identify leave packets 1 + 2
  leave_packets = {}

  # help identify leave 3 packets  
  leave_3_packets = {}

  # help identify rejoin request packets
  request_packets = {}

  # help identify network status packets 1
  network_status_1 = []

  # help identify network status packets 2 3
  network_status_2 = []

  # help identify network status packets 3
  network_status_3_1 = []

  network_status_3_2 = []

  network_status_3_3 = []

  network_status_3_4 = []
  
  # help identify network stats packets 4
  network_status_4 = []

  # help identify route record packets 1
  route_record_1 = []

  # route record packets 2
  route_record_2 = []

  # route record packets 3
  route_record_3_1 = []

  route_record_3_2 = []

  route_record_3_3 = []

  route_record_3_4 = []

  # route record packets 4
  route_record_4 = []

  # keeps track of the main router
  # comes from the first device announcement
  da_main = ""

  # help identify the route records data.len 4 that come before the device anouncments
  rra = ""
  rrb = ""

  # helps identify the route records data.len 4 w/ packets that are mixed up w the device announcements
  da_rando = ""

  # keeps track of the last device announcement time
  da_time = 0


#  # frames that might be leave packets, but need the ZED
#  # maps network_id : mac_id
#  leave_zed = {}
  
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

  # csv_file = "results.csv"

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

        # if frame.number == '24222':
        #   print(d_announce)
        #   print(ab0)
        
        
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
        
        # if (frame.number == '52616'):
        #   print('zbee_aps' in frame.protocols)
        
        try:
          if 'zbee_nwk' in dir(pk):
            zbee = pk.zbee_nwk
            # csv_src = wpan.src16
            # csv_dst = wpan.dst16


                
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

                  # identify between leave + rejoin request packet
                  # check_response = {time, (src, dst)}
                  if check_response:
                    delete = []
                    for time, ip in check_response.items():
                      if (zbee.src == ip[1]):
                        if (zbee.dst == ip[0]):
                          elapsed = float(frame.time_epoch) - float(time)
                          if elapsed <= 60: # rejoin request
                            rejoin_request = rejoin_request + 1
                            request_packets[time] = (ip[0], ip[1])
                            delete.append(time)
                          elif elapsed > 60: # leave
                            leave_3 = leave_3 + 1
                            leave_3_packets[time] = (ip[0], ip[1])
                            delete.append(time)
                            # try:
                            #   d_announce.remove(ip[0])
                            # except KeyError:
                            #   continue
                    for t in delete:
                      del check_response[t]

                  if zbee.src != '0x00000000':
                    zbee_r.add(zbee.src)
                  elif zbee.src == '0x00000000':
                    zbee_c.add(zbee.src64)
                    if zbee.src_route == True:
                      zbee_r.add(zbee.dst)
                    elif zbee.src_route == False:
                      zbee_ed.add(zbee.dst)
                  
                  continue
                
                   


                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                # ~~~~~~~~ DATA.LEN == 2 ~~~~~~~~~~~~~~~
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                if zbee.data_len == '2':
                  
                  # ===== leave packets ===========
                  # dst : zc, zr, zed, 0xfffd
                  # src : zc, zr, zed


                  if (zbee.dst == '0x0000fffd') or (zbee.dst in zbee_ed): # 1
                    leave_1 = leave_1 + 1
                    leave_packets[frame.number] = (zbee.src, zbee.dst)
                    # try:
                    #   d_announce.remove(zbee.src)
                    # except KeyError:
                    #   pass
                    continue
                     
                  if (zbee.dst != '0x0000fffc'):
                    if (zbee.src == '0x00000000'): # 2
                      leave_2 = leave_2 + 1
                      leave_packets[frame.number] = (zbee.src, zbee.dst)
                      # try:
                      #   d_announce.remove(zbee.src)
                      # except KeyError:
                      #   pass
                      continue
                       
                    else: # 3
                      check_response[frame.time_epoch] = (zbee.src, zbee.dst)
                       
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

                continue
                 
              
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              # ~~~~~ DATA.LEN == 3 ~~~~~~~~~~~~
              # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

              # ===== end device timeout request =======
              # request dst : zc, zr
              # request src : zed

              if (zbee.data_len == '3') and ((zbee.dst == '0x00000000') or (zbee.dst in zbee_r)) and (zbee.src in zbee_ed):
                edt_request = edt_request + 1
  
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

                  continue
                  

                 
                # ====== network report packets ========
                # destination : zc = 0x0000
                # source : zr

                if (zbee.ext_dst == '0') and (zbee.dst == '0x00000000'):
                  network_report = network_report + 1
                  #csv_packet = 'network report packet'
                  
                  zbee_r.add(zbee.src)
                  zbee_c.add(zbee.dst64)

                  continue
                  
                   

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
                  
                  continue

                
                a = d_announce[0]
                try:
                  b = d_announce[1]
                except IndexError:
                  b = False
                try:
                  c = d_announce[2]
                  d = d_announce[3]
                except IndexError:
                  pass

                # # ===== network status packets ========
                # # dst : zc, zr, zed, 0xfffd
                # # src : zc, zr, zed
                
                # if (zbee.data_len == '2' or zbee.data_len == '4') and zbee.dst != '0x00000000' and wpan.src16 != zbee.src and (zbee.dst == '0x0000fffd' or zbee_dst in zbee_ed):
                #   # 1
                #   network_status = network_status + 1
                #   network_status_1.append(frame.number)
                #   # print(f'ns packet 1 : {frame.number} : {zbee.dst}')
                #   #csv_packet = 'network status packet'

                #   if zbee.src != '0x00000000':
                #     #zbee_red.add(zbee.src)
                #     #if zbee.dst != '0x0000fffd':
                #       #if zbee.dst != '0x00000000':
                #         # zbee_red.add(zbee.dst)
                #     if zbee.dst == '0x00000000':
                #       zbee_c.add(zbee.dst64)

                #   elif zbee.src == '0x00000000':
                #     zbee_c.add(zbee.src64)
                #     if zbee.dst != '0x0000fffd':
                #       if zbee.src_route == True:
                #         zbee_r.add(zbee.dst)
                #       elif zbee.src_route == False:
                #         zbee_ed.add(zbee.dst)

                # if zbee.data_len == '4' and wpan.src16 == zbee.src:
                #   # 2
                #   network_status = network_status + 1
                #   network_status_2.append(frame.number)
                #   # print(f'ns packet 2 wpan src : {frame.number}')
                #   #csv_packet = 'network status packet'
                  
                #   if zbee.src != '0x00000000':
                #     #zbee_red.add(zbee.src)
                #     #if zbee.dst != '0x0000fffd':
                #       #if zbee.dst != '0x00000000':
                #         #zbee_red.add(zbee.dst)
                #     if zbee.dst == '0x00000000':
                #       zbee_c.add(zbee.dst64)

                #   elif zbee.src == '0x00000000':
                #     zbee_c.add(zbee.src64)
                #     if zbee.dst != '0x0000fffd':
                #       if zbee.src_route == True:
                #         zbee_r.add(zbee.dst)
                #       elif zbee.src_route == False:
                #         zbee_ed.add(zbee.dst)
                  
                #   continue
                
                # if (zbee.data_len == '2') and (wpan.src16 != zbee.src):
                #   # 3
                #   network_status = network_status + 1
                #   network_status_4.append(frame.number)
                #   # print(f'ns packet 3 : {frame.number}')
                #   #csv_packet = 'network status packet'
  
                #   if zbee.src != '0x00000000':
                #     #zbee_red.add(zbee.src)
                #     #if zbee.dst != '0x0000fffd':
                #       #if zbee.dst != '0x00000000':
                #       # zbee_red.add(zbee.dst)
                #     if zbee.dst == '0x00000000':
                #       zbee_c.add(zbee.dst64)

                #   elif zbee.src == '0x00000000':
                #     zbee_c.add(zbee.src64)
                #     if zbee.dst != '0x0000fffd':
                #       if zbee.src_route == True:
                #         zbee_r.add(zbee.dst)
                #       elif zbee.src_route == False:
                #         zbee_ed.add(zbee.dst)

                #   continue


                # # ===== route record packets ===========
                # # dst : zc, zr
                # # src : zc, zr, zed

                
                # if zbee.dst != '0x0000fffc':
                #   if ((zbee.data_len == '6') or (zbee.data_len == '8') or (zbee.data_len == '10')):
                #     # 1 route record
                #     route_record = route_record + 1
                #     route_record_1.append(frame.number)
                #     #csv_packet = 'route record packet'
                    
                #     #if zbee.src != '0x00000000':
                #     #  zbee_red.add(zbee.src)
                #     if zbee.src == '0x00000000':
                #       zbee_c.add(zbee.src64)
                    
                #     if zbee.dst != '0x00000000':
                #       zbee_r.add(zbee.dst)
                #     elif zbee.dst == '0x00000000':
                #       zbee_c.add(zbee.dst64)
                    
                #     continue
                   
                #   if zbee.ext_dst == '1' and (zbee.data_len != '2') and (zbee.data_len != '4') and (zbee.data_len != '6') and (zbee.data_len != '8') and (wpan.src16 != zbee.src):
                #     # 2 route record
                #     route_record = route_record + 1
                #     route_record_2.append(frame.number)
                #     #csv_packet = 'route record packet'
                    
                #     # if zbee.src != '0x00000000':
                #     #  zbee_red.add(zbee.src)
                #     if zbee.src == '0x00000000':
                #       zbee_c.add(zbee.src64)
                    
                #     if zbee.dst != '0x00000000':
                #       zbee_r.add(zbee.dst)
                #     elif zbee.dst == '0x00000000':
                #       zbee_c.add(zbee.dst64)
                    
                #     continue
                      
                #   a = d_announce[0]
                #   b = d_announce[1]

                #   if zbee.ext_dst == '1' and zbee.dst != '0x0000fffd' and wpan.src16 == zbee.src and zbee.data_len == '2':
                #     # 3 route record
                #     route_record = route_record + 1
                #     route_record_4.append(frame.number)
                #     #csv_packet = 'route record packet'
                    
                #     previous[5] == False
                #     if zbee.src == a:
                #       if wpan.src16 == a:
                #         if wpan.dst16 == b:
                #           ab0 = False
                #         elif wpan.dst16 == '0x00000000':
                #           ab0 = True
                #     elif zbee.src == b:
                #       if wpan.src16 == b:
                #         if wpan.dst16 == '0x00000000':
                #           ab0 = False
                #           ba0 = True
                #         elif wpan.dst16 == a:
                #           ba0 = False

                #     #if zbee.src != '0x00000000':
                #     #  zbee_red.add(zbee.src)
                #     if zbee.src == '0x00000000':
                #       zbee_c.add(zbee.src64)
                    
                #     if zbee.dst != '0x00000000':
                #       zbee_r.add(zbee.dst)
                #     elif zbee.dst == '0x00000000':
                #       zbee_c.add(zbee.dst64)
                    
                #     continue


                # ===== network status packets ========
                # dst : zc, zr, zed, 0xfffd
                # src : zc, zr, zed
                # ===== route record packets ===========
                # dst : zc, zr
                # src : zc, zr, zed

                if zbee.src == previous[0] and zbee.dst == previous[1] and wpan.src16 == previous[2] and wpan.dst16 == previous[3] and zbee.data_len == previous[4]:
                  if previous[5]:
                    network_status_3_1.append(frame.number)
                    continue
                  else:
                    route_record_3_1.append(frame.number)
                    continue
                
                previous = [zbee.src, zbee.dst, wpan.src16, wpan.dst16, zbee.data_len, None]
                if len(d_announce) == 0:
                  continue
                
                one = zbee.src
                two = zbee.dst
                three = wpan.src16
                four = wpan.dst16

                if zbee.data_len == '2':
                  route_record_3_2.append(frame.number)
                  previous[5] == False
                  if one == a:
                    if three == a:
                      if four == '0x00000000':
                        ab0 = True
                      elif four == b:
                        ab0 = False
                        ba0 = False
                  elif one == b:
                    if three == b:
                      if four == '0x00000000':
                        ab0 = False
                        ba0 = True
                      elif four == a:
                        ba0 = False
                  elif one != a and one != b: 
                    if one == three and two == '0x00000000' and three != four and four == da_main:
                      rra = one                
                      rrb = four
                elif zbee.data_len == '4':
                  previous[5] = True
                  if one == a:
                    if three == a:
                      if four == b or four == '0x00000000':
                        ab0 = True
                        network_status_3_2.append(frame.number)
                      else:
                        network_status_3_2.append(frame.number)
                    elif three == b:
                      if four == '0x00000000':
                        if ab0:
                          network_status_3_3.append(frame.number)
                          # ab0 = False
                        else:
                          route_record_3_3.append(frame.number)
                          previous[5] = False
                      elif four == a:
                        network_status_3_2.append(frame.number)
                      elif four == d:
                        route_record_3_2.append(frame.number)
                        previous[5] = False
                  elif one == b:
                    if three == a:
                      if four == '0x00000000':
                        if ba0:
                          network_status_3_4.append(frame.number)
                        else:
                          route_record_3_4.append(frame.number)
                          previous[5] = False
                      if four == b:
                        network_status_3_2.append(frame.number)
                    elif three == b:
                      if four == '0x00000000':
                        ab0 = False
                        network_status_3_2.append(frame.number)
                      elif four == a:
                        ba0 = True
                        network_status_3_2.append(frame.number)
                      else:
                        network_status_3_2.append(frame.number)
                    elif three == d:
                      if four == '0x00000000':
                        network_status_3_2.append(frame.number)
                  
                  try:
                    if one == d:
                      if three == c and four == '0x00000000':
                        route_record_3_2.append(frame.number)
                        previous[5] = False
                        continue
                  except UnboundLocalError:
                    pass

                  if one == da_rando and two == '0x00000000' and three == da_main and four == '0x00000000':
                    route_record_3_2.append(frame.number)
                    previous[5] = False
                  elif one == rra and three == rrb:
                    if two == '0x00000000' and four == '0x00000000':
                      route_record_3_2.append(frame.number)
                      previous[5] = False
                elif zbee.data_len == '6':
                  if one == d:
                    if three == d and four == '0x00000000':
                      route_record_3_2.append(frame.number)
                      previous[5] = False

            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            # ~~~~~~~ WPAN.FRAME_TYPE == 0x01 ~~~~~~~
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          
            # ===== device announcements ============
            # dst : 0xfffd
            if (wpan.frame_type == '0x00000001'):
              if (zbee.frame_type == '0x00000000') and (zbee.data_len == '20') and (zbee.dst == '0x0000fffd'):

                # if elapsed > 1 sec = new device announcement set
                # if elapsed < 1 sec = same da set
                t = float(frame.time_epoch)
                if t - da_time > 60:
                  d_announce = [zbee.src]
                da_time = t

                # x = [frame.time_epoch, zbee.src]
                ab0 = False
                # ba0 = False

                # for the first da = "main"
                if not da_main:
                  da_main = zbee.src
                
                # checks wpan src + dst & makes sure not already added, 0x0000, or 0xffff
                ws = wpan.src16
                if ws in d_announce or ws == '0x00000000' or ws == '0x0000ffff':
                  wd = wpan.dst16
                  if wd in d_announce or wd == '0x00000000' or wd == '0x0000ffff':
                    da_rando = zbee.src
                    continue
                  else:
                    da_rando = ""
                    d_announce.append(wd)
                else:
                  da_rando = ""
                  d_announce.append(ws)

                previous = [0, 0, 0, 0, 0, None]
                continue
              

            
            
          #results_writer.writerow([f'{csv_time}', f'{csv_src}', f'{csv_dst}', f'{csv_len}', f'{csv_protocol}', f'{csv_frame_num}', f'{csv_packet}'])
        except AttributeError:
          pass

    except KeyboardInterrupt:
      print("\n\nINTERRRUPPTEDDDD")
    

    mac_network = {}
    for network, mac in network_mac.items():
      try:
        mac_network[mac].add(network)
      except KeyError:
        mac_network[mac] = {network}

    
    finish()

    # writes into results file
    # call ./checker.py (authomatically pulls from results)
    # input frame numbers into checker
    # test.txt will contain which ones are in and which ones aren't
    f = open("results.txt", "w")
    f.write(f"{network_status_3_1}\n{network_status_3_2}\n{network_status_3_3}\n{network_status_3_4}\n{route_record_3_1}\n{route_record_3_2}\n{route_record_3_3}\n{route_record_3_4}")
    f.close()

    # print(f"\nnetwork status packets 1 : {len(network_status_1)}")
    # # for p in network_status_1:
    # #   print(f"     {p}")

    # print(f"\nnetwork status packets 2 : {len(network_status_2)}")
    # print(network_status_2)
    # # for p in network_status_packets:
    # #   print(f"     {p}")

    # print(f"\nnetwork status packets 3 1 : {len(network_status_3_1)}")
    # print(network_status_3_1)
    # print(f"\nnetwork status packets 3 2 : {len(network_status_3_2)}")
    # print(network_status_3_2)
    # print(f"\nnetwork status packets 3 3 : {len(network_status_3_3)}")
    # print(network_status_3_3)
    # print(f"\nnetwork status packets 3 4 : {len(network_status_3_4)}")
    # print(network_status_3_4)
    # # print(network_status_3)

    # print(f"\nnetwork status packets 4 : {len(network_status_4)}")
    # # print(network_status_4)
    # # for p in network_status_4:
    # #   print(f"     {p}")

    # print(f'\nroute record packets 1 : {len(route_record_1)}')
    # print(f'\nroute record packets 2 : {len(route_record_2)}')
    # print(f'\nroute record packets 3 1 : {len(route_record_3_1)}')
    # print(route_record_3_1)
    # print(f'\nroute record packets 3 2 : {len(route_record_3_2)}')
    # print(route_record_3_2)
    # print(f'\nroute record packets 3 3 : {len(route_record_3_3)}')
    # print(route_record_3_3)
    # print(f'\nroute record packets 3 4 : {len(route_record_3_4)}')
    # print(route_record_3_4)
    # # print(route_record_3)
    # print(f'\nroute record packets 4 : {len(route_record_4)}')
    # print(route_record_4)
    # # for p in route_record_4:
    # #   print(f"     {p}")



    print(f'\nmac : network_id\n{mac_network}')

    print("\n\nzbee coordinator addresses:")
    for c in zbee_c:
      print(f"     {c}")

    print("\n\nzbee router addresses:")
    for r in zbee_r:
      print(f"     {r}")

    print("\n\nzbee end devices addresses:")
    for ed in zbee_ed:
      print(f"     {ed}")

    network_status = len(network_status_1) + len(network_status_2) + len(network_status_3_1) + len(network_status_3_2) + len(network_status_3_3) + len(network_status_3_4) + len(network_status_4)
    route_record = len(route_record_1) + len(route_record_2) + len(route_record_3_1) + len(route_record_3_2) + len(route_record_3_3) + len(route_record_3_4) + len(route_record_4)
    print("\n\n\n")
    # print(f"number of route request packets : {route_request}")
    # print(f"number of route reply packets : {route_reply}")
    # print(f"number of network status packets : {network_status}")
    # # print(f"number of leave packets : {leave_1} : {leave_2} : {leave_3 + len(check_response)}")
    # print(f"number of leave packets : {leave_1 + leave_2 + leave_3 + len(check_response)}")
    # print(f"number of route record packets : {route_record}")
    # print(f"number of rejoin request packets : {rejoin_request}")
    # print(f"number of rejoin response packets : {rejoin_response}")
    # print(f"number of link status packets : {link_status}")
    # print(f"number of network report packets : {network_report}")
    # print(f"number of network update packets : {network_update}")
    # print(f"number of end device timeout request packets : {edt_request}")
    # print(f"number of end device timeout response packets : {edt_response}")

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
    print(f"number of leave packets : {leave_1 + leave_2 + leave_3 + len(check_response)}")
    print(f"number of rejoin request packets : {rejoin_request}")
    print("======")
    print(sys.argv[1])
  else:
    print("please give me a file")
    sys.exit()  
  

if __name__ == "__main__":
  parse()
