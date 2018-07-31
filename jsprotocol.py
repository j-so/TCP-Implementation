from scapy.all import *

# A new protocol that looks a lot like TCP

class JSTCP(Packet):
	name = "JSTCP"
	fields_desc = [   ShortEnumField("sport", 53, TCP_SERVICES),
	                ShortEnumField("dport", 53, TCP_SERVICES),
	                ShortField("ackseq", None),
	                XShortField("chksum", None),
	                ShortField("seq", None),
	                ShortField("window", 0),
	                FlagsField("flags", 0, 32, ["A", "P", "F", "S", "R", "SA"]),
	                IntField("left", 0),
	                IntField("right", 0), ]

	def post_build(self, pkt, pay):
		p = pkt+pay
		if self.chksum is None:
			if isinstance(self.underlayer, IP):
				psdhdr = struct.pack("!4s4sHH",
			                        inet_aton(self.underlayer.src),
			                        inet_aton(self.underlayer.dst),
			                        self.underlayer.proto,
			                        len(p))
				ck=checksum(psdhdr+p)
				p=p[:6]+chr(ck >> 8)+chr(ck & 0xff)+p[8:]
			else:
				warning("No IP underlayer to compute checksum. Leaving null.")
		return p
