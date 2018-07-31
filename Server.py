from TCPConnection import *

so = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
so.setsockopt(socket.SOL_IP, socket.IP_HDRINCL,1)
so.bind(('0.0.0.0',7890))

conn = TCPConnection(so, 7890)
conn.acceptConnection()

while True:
    message = conn.receive()
    if message == False:
      break
    else:
      print message
