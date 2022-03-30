from .Packet import *
import socket
from . import Flow

#get median of interarrival time
def getMedian(vallist):
	vallist.sort(key = lambda val:val[0])
	tot = 0
	cfreq = []
	for val in vallist:
		tot += val[1]
		cfreq.append(tot)
	medianindex = tot / 2
	i = 0
	while medianindex > cfreq[i]:
		i += 1
	return vallist[i][0]

#defines a superflow
class SuperFlow(Flow.Flow):

	def __init__(self, fields, bin_width, ipt_bin_width):
		
		# some parameters to limit flow characteristics
		self.MAX_MTU = 1500
		self.MAX_IPT = 3600
		# initialize the parameters for this flow's flow marker
		self.bin_width = bin_width
		self.ipt_bin_width = ipt_bin_width
		self.quantized_pl_bin_upper_limit = self.MAX_MTU // self.bin_width
		self.quantized_ipt_bin_upper_limit = self.MAX_IPT // self.ipt_bin_width

		if fields == None:
			self.ip1 = None
			self.ip2 = None
			self.key = None
			self.n_packet1 = 0
			self.n_byte1 = 0
			self.t_start1 = 0
			self.t_end1 = 0	
			self.t_interarrival1 = []
			self.n_packet2 = 0
			self.n_byte2 = 0	
			self.t_start2 = 0
			self.t_end2 = 0
			self.t_interarrival2 = []
		else:
			self.ip1 = socket.inet_aton(fields[0])
			self.ip2 = socket.inet_aton(fields[1])
			self.key = self.ip1 + self.ip2
			self.n_packet1 = int(fields[2])
			self.n_byte1 = int(fields[3])
			self.t_start1 = float(fields[4])
			self.t_end1 = float(fields[5])
			self.t_interarrival1 = [(float(fields[6]),self.n_packet1)]						
			self.n_packet2 = int(fields[7])
			self.n_byte2 = int(fields[8])	
			self.t_start2 = float(fields[9])
			self.t_end2 = float(fields[10])
			self.t_interarrival2 = [(float(fields[11]),self.n_packet2)]
			
			# UPDATE flow markers by picking from input fields
			# fields 0-11 are flow fields, 
			next_field = 12

			# onwards until self.quantized_pl_bin_upper_limit is the pl_flowmarker
			self.pl_flow_marker = {}
			for this_bin in range(1, self.quantized_pl_bin_upper_limit + 1):
				self.pl_flow_marker[this_bin] = int(fields[next_field])
				next_field += 1

			# then afterwards, all fields are self.quantized_ipt_bin_upper_limit
			self.ipt_flow_marker = {}
			for this_bin in range(1, self.quantized_ipt_bin_upper_limit + 1):
				self.ipt_flow_marker[this_bin] = int(fields[next_field])
				next_field += 1

	#get median of interarrival time irrespective of direction
	def getInterArrivaltime(self):
		combined = self.t_interarrival1 + self.t_interarrival2
		if len(combined) > 0:
			return getMedian(combined)
		return 0	
	
	#interarrival time for direction1(arbitrary)
	def getInterArrivaltime1(self):
		if len(self.t_interarrival1) > 0:
			return getMedian(self.t_interarrival1)
		return 0
	
	#interarrival time for direction2(arbitrary)
	def getInterArrivaltime2(self):
		if len(self.t_interarrival2) > 0:
			return getMedian(self.t_interarrival2)
		return 0
