from TCPConnection import *

so = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
so.setsockopt(socket.SOL_IP, socket.IP_HDRINCL,1)
so.bind(('0.0.0.0',56789))

conn = TCPConnection(so, 56789)
conn.initiateConnection(7890)

while True:
  s = raw_input("<56789> ")
  if s == "quit":
    conn.initiateClose()
    break
  else:
    conn.sendMessage(s)