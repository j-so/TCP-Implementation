# A class dealing with the sending and receiving of packets between two hosts
# TCP Tahoe information from this link: http://condor.depaul.edu/jkristof/technotes/congestion.pdf

import itertools
import threading
import time
import socket
import select
from sets import Set
from scapy.all import *
from jsprotocol import JSTCP

class TCPConnection():

  sport = 0
  dport = 0
  mtu = 500

  packet_list = []
  max_size = 20
  sock = 0
  slow_start_window = 1
  CA = False
  CAwindow = 0

  # Jacobson Karels init
  alpha = 0.875
  delta = 1/4
  miu = 1
  psi = 4
  estimated_rtt = 4
  deviation = 0.75
  sum_rtt = 0
  count_rtt = 0

  close = False
  verbose = False

  def __init__(self, my_sock, sport):
    self.sock = my_sock
    self.sport = sport
    self.window = self.slow_start_window # Slow Start
    self.receive_window = self.max_size # Set to max

  # Jacobson Karels Algorithm (finding RTO using mean deviation)
  def calcRTO(self, new_rtt):
    diff = new_rtt - self.estimated_rtt
    self.estimated_rtt = self.alpha * self.estimated_rtt + (1 - self.alpha) * new_rtt
    self.deviation = self.deviation + self.delta*(abs(diff) - self.deviation)
    self.retrans_timer = self.miu * self.estimated_rtt + self.psi * self.deviation +1
    #print self.retrans_timer

  def acceptConnection(self):
    # wait for a packet wtih syn flag up
    pkt, addr = self.sock.recvfrom(65565)
    
    if addr[0] == '127.0.0.1':
      pack = JSTCP(IP(pkt).load)
      recv_flags = pack.sprintf("%JSTCP.flags%")
      # syn flag up!
      if "S" in recv_flags:
        self.dport = pack.sport

        index = 0
        while True:

          # For now
          self.retrans_timer = 5

          # Send Syn-Ack
          start_time = time.time()
          send(IP()/JSTCP(sport = self.sport, dport=self.dport, flags="SA", seq = 0, ackseq = pack.seq+1, window = self.receive_window), verbose = self.verbose)
        
          # Wait for Ack
          win, ackseq, left, right = self.receiveFlag("A")
          
          if win != -1:
            end_time = time.time()
            self.calcRTO(start_time-end_time) # Find RTO

            print "Connection has been made with port "+str(self.dport)
            break
          else:
            index = index+1


  def initiateConnection(self, dport):
    self.dport = dport

    # send Syn
    start_time = time.time()
    send(IP()/JSTCP(sport = self.sport, dport=self.dport, flags="S", seq = 0, window = self.receive_window), verbose = self.verbose)

    while True:
      # wait for Syn-Ack
      pkt, addr = self.sock.recvfrom(65565)
      if addr[0] == '127.0.0.1':
        pack = JSTCP(IP(pkt).load)
        # send Ack, finished
        recv_flags = pack.sprintf("%JSTCP.flags%")
        if pack.dport == self.sport and "SA" in recv_flags:
          end_time = time.time()
          self.calcRTO(start_time-end_time) # Find RTO
          send(IP()/JSTCP(sport = self.sport, dport=self.dport, flags="A", ackseq = 10, seq = pack.seq+1, window = self.receive_window), verbose = self.verbose)
          print pack.seq+1
          print "Connection has been made with port "+str(self.dport)
          self.close = True
          break
      
  def initiateClose(self):
    self.sendFin()
    win, ackseq, left, right = self.receiveFlag("A")
    if win!=-1:
      win, ackseq, left, right = self.receiveFlag("F")
      if win!=-1:
        self.send_ack(2, 0, 0)
        self.sock.close()
        print "Connection has closed with port " + str(self.dport)

  def handleClose(self):
    self.send_ack(2, 0, 0)
    self.sendFin()
    win, ackseq, left, right = self.receiveFlag("A")
    if win!=-1:
      self.sock.close()
      self.close = True
      print "Connection has closed with port " + str(self.dport)


  def sendFin(self):
    send(IP()/JSTCP(sport = self.sport, dport=self.dport, flags="F", ackseq = 10, seq = 1, window = self.receive_window), verbose = self.verbose)

  # Returns start time for calculating sample RTT
  def sendBuffer(self, buff):
    for m in buff:
      m.window = 1 # TODO
      send(m, verbose = self.verbose)
      #time.sleep(1)
    return time.time()

  def send_ack(self, seq, left, right):
    pkt = (IP()/JSTCP(sport = self.sport, dport = self.dport, flags = "A", ackseq = seq, window = self.receive_window, chksum = 0x0, seq = seq, left = left, right = right))
    send(pkt, verbose = self.verbose)

  def receiveFlag(self, flag):
    curr_time = 0
    start_time = 0
    
    while True:
        
      # return -1 if time out
      try:
        # Set the timeout for self.socket, start timer
        self.sock.settimeout(self.retrans_timer-(curr_time-start_time))
        start_time = time.time()
        message, addr = self.sock.recvfrom(65565)
      except socket.timeout:
        curr_time = time.time()
        self.sock.settimeout(None)
        return -1, -1, -1 , -1

      # record time
      curr_time = time.time()
      self.sock.settimeout(None)

      # If wrong type of packet, keep recieving
      if addr[0] != "127.0.0.1":
        continue

      # If not an ack packet, just ignore it and continue
      pkt = JSTCP(IP(message).load)

      # Wait for the right packet to come along
      if pkt.dport != self.sport:
        continue
      recv_flags = pkt.sprintf("%JSTCP.flags%")
      if flag not in recv_flags:
        continue

      # Return window and ack index
      left = -1
      right = -1
      if flag=="A":
        left = pkt.left
        right = pkt.right

      return pkt.window, pkt.ackseq, left, right

  def verifyChecksum(self, pkt):
    given_chksum = pkt.chksum
    # Recompute through scapy
    del pkt.chksum
    packet=IP()/pkt
    t = str(packet)
    pack = JSTCP(IP(t).load)
    recomputedChecksum=pack.chksum

    if given_chksum != recomputedChecksum:
      return False
    else:
      return True

  def receiveMessage(self, delayed_ack_time):
    curr_time = 0
    start_time = 0
    
    while True:
      # Set the timeout for self.socket, start timer
      if delayed_ack_time > 0:
        self.sock.settimeout(delayed_ack_time-(curr_time-start_time))
        start_time = time.time()

        try:
          message, addr = self.sock.recvfrom(65565)
        except socket.timeout:
          self.sock.settimeout(None)
          return -1, -1, False

        curr_time = time.time()
        self.sock.settimeout(None)

      else:
        self.sock.setblocking(1)
        self.sock.settimeout(None)
        message, addr = self.sock.recvfrom(65565)

      # If wrong place, keep waiting
      if addr[0] != "127.0.0.1":
        continue
      
      pkt = JSTCP(IP(message).load)

      # If wrong port, keep waiting
      if pkt.dport != self.sport:
        continue

      if self.verifyChecksum(pkt):
        last = False
        recv_flags = pkt.sprintf("%JSTCP.flags%")
        if "P" in recv_flags: # last segment!
          last = True
        if "F" in recv_flags: # close connection...
          self.handleClose()
          return -2, -2, False

        # Return window and ack index
        return pkt.seq, pkt.load, last

      else:
        return -1, -1, False


  # Split the message into a list
  def splitMessage(self, message):
    #size = 500
    message_bytes = message.encode()
    num = int(math.ceil(len(message_bytes)/float(self.mtu)))
    packages = [0] * (num+1)
    start = 0
    for j in range(1, num):
      packages[j] = IP()/JSTCP(sport = self.sport, dport = self.dport, seq = j, flags = "A")/message_bytes[start:start+self.mtu]
      start = start + self.mtu

    packages[num] = IP()/JSTCP(sport = self.sport, dport = self.dport, seq = num, flags = "P")/message_bytes[start:]
    return packages

  # Method that sends a full string message, deals with full send mechanism
  def sendMessage(self, string_message):

    self.empty_socket()
    packet_list = self.splitMessage(string_message)
    done = False
    last_sent_idx = 1
    index = 1
    prevIndex = index

    # main loop: until full message sent and acked
    while not done:

      # Fill/send buffer and break once we get an Ack
      while True:
        buff = []

        # so the next line does not access past the last index
        if self.window > (len(packet_list) - last_sent_idx):
          self.window = (len(packet_list) - last_sent_idx)
         
        for i in range(last_sent_idx, (last_sent_idx+self.window)):
          buff.append(packet_list[i])

        # Initialize
        win = self.window

        # Send buffer and wait for ack
        # whilst calculating rtt time
        start_time = self.sendBuffer(buff)
        win, index, left, right = self.receiveFlag("A")
        end_time = time.time()

        # We got an ACK!
        if(index > -1):

          last_sent_idx+=self.window # update last sent
          self.calcRTO(start_time-end_time) # update RTO

          if self.CA and self.slow_start_window >= self.CAwindow:
            self.CAwindow = win # set CAwindow as advertised
            self.slow_start_window += 1 # increase linearly
          else: # We are either in Slow Start, or CA is still under the threshold
            self.slow_start_window *= 2 # update slow_start_window

          break

        # If we are here, we just timed out :(
        # Just entering CA: set new window, begin slow start at 1, and set state CA to true
        if not self.CA:
          self.CAwindow = self.window // 2
          if self.CAwindow < 2:
            self.CAwindow = 2
          self.slow_start_window = 1
          self.CA = True

        if self.CA: # congestion avoidance state, maintain halfpoint window
          win = self.CAwindow

      # Choose the minimum window size
      self.window = min(self.slow_start_window, win)

      # reset the buffer
      buff = []
      self.window = min(win, self.slow_start_window) # Set to the minimum

      if index < last_sent_idx:
        for i in range(index, left+1):
          buff.append(packet_list[i])
        self.window -= left - index+1
        if right < last_sent_idx-1:
          buff.append(packet_list[right+1])
          self.window -= 1

      # check if all packets have been recieved
      if index >= len(packet_list):
        done = True

    # cleaning up
    packet_list = []
    self.empty_socket()
    return done

  # Handles the recieving of an entire message.
  # Returns a full string.
  # Delayed Ack Timer is set to 200 ms, as is common with most systems.
  def receive(self):

    if self.close:
      return False

    self.empty_socket()

    # init. vars
    done = True
    list_indices = []
    last_packet_idx = 0
    buff = []
    packet_list = []
    last_segment = -2
    sack = []
    L = False
    s = -1
    m = ""
    l = False
    left = 0

    # Get first packet
    while s==-1:
      s,m,l = self.receiveMessage(0)

    # If -2, then the connection has closed
    if s==-2:
      return False

    buff.append((s,m))

    if l:
      self.receive_window = 0
      L = True

    done = False

    # main loop
    while not done:
      # add to expected indices
      for i in range(last_packet_idx+1,last_packet_idx+self.receive_window+3):
        if i not in list_indices:
          list_indices.append(i)


      # listen for packets
      timer = 0
      start_time = time.time()
      while self.receive_window > 0 and timer < 0.01:
        s,m,l = self.receiveMessage(self.retrans_timer*2)
        timer = abs(start_time - time.time())

        if(s==-1):
          break
        if l:
          L = True

        # A message is received: update buffer and window size
        buff.append((s,m))
        self.receive_window = self.receive_window -1

      # check the recieved packets off the list of those expected
      for i, j in buff:
        if i in list_indices:
          sack.extend([i])
          list_indices.remove(i)
          packet_list.append((i,j))

      ack = list_indices[0]
      left = ack
      maxisack = max(sack)
      while True:
        if (left+1) in sack:
          break
        left+=1
        if left > maxisack:
          break

      right = left
      while True:
        if (right+1) in sack:
          right += 1
        else:
          break

      # update window size
      self.receive_window = self.max_size
      
      # send ack with the sack
      self.send_ack(ack, left, right)

      # save the recieved packets (no order needed for this step)
      last_packet_idx = (max(packet_list))[0]

      #check if we recieved last packet
      if L:
        last_segment = last_packet_idx
      
      # clear buffer
      buff = []
      
      # check if we are done recieving packets
      if last_segment == list_indices[0]-1:
        done = True

    
    full_message = self.constructString(packet_list, last_segment)

    self.empty_socket()
    packet_list = []

    return full_message

  def constructString(self, packet_list, last_segment):
    # interpret packets
    recieved_string = ['']*last_segment
    for idx, ch in packet_list:
      recieved_string[idx-1] = ch

    # return recieved string
    return ''.join(recieved_string)

  def empty_socket(self):
    self.sock.setblocking(0)
    while True:
      try:
        data, addr = self.sock.recvfrom(65565)
      except socket.error:
        return






