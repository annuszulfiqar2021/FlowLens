from .P2P_CONSTANTS import *
from .Packet import *

#input: list of packets, timegap - real number
#return val: list of flows
#
#merges collection of packets(objects) into collection of flows(many-to-one)
#Working: group packets with same ip-pair(direction irrelevant) and merge all packets for
#which |packet1.time - packet2.time| < threshold(timegap)

# per_pkt_hist_filename is the file where we fill per-packet histograms with each incoming packet
def packetsToFlows(packets, class_label, per_pkt_hist_filename, timegap, bin_width, ipt_bin_width):
	#sanity check for 0 packets 
	if len(packets) == 0:
		return None

	outputflows = []
	
	#perform a radix-sort to group together packets
	#with same ip-pairs(packet.key represents an ip-pair) 
	#and sort these packets according to timestamp
	packets.sort(key = lambda packet:packet.timestamp)
	packets.sort(key = lambda packet:packet.key)
	
	# quantize the timegap according to ipt_bin_width
	timegap	= timegap # // ipt_bin_width

	to_write = []
	# open per-pkt histogram file to write into..
	with open(per_pkt_hist_filename, 'w') as per_pkt_csvfile:
		nextflow = Flow(None, bin_width, ipt_bin_width)
		for nextpacket in packets:
			#if ip-pairs dont match or time-difference of prev and current packet greater
			#than timegap, create a new flow 
			if (nextflow.key != nextpacket.key) or ((nextpacket.timestamp - nextflow.getEnd()) > timegap):
				nextflow = Flow(nextpacket, bin_width, ipt_bin_width)
				outputflows.append(nextflow)
			#if not then add packet to previous flow
			else:
				nextflow.addPacket(nextpacket)
			# pick this running flow's current flow markers with this packet just added
			per_pkt_pl_flow_marker_str, per_pkt_ipt_flow_marker_str = nextflow.getFlowMarkersAsCommaSeparatedStrings()
			# append the next string to be written for this flow
			to_write.append(per_pkt_pl_flow_marker_str + ',' + per_pkt_ipt_flow_marker_str + ',' + class_label)
		# write these to the per-pkt histogram file
		per_pkt_csvfile.write("\n".join(to_write))
		per_pkt_csvfile.close()
	return outputflows

#same as function packetsToFlow but merges flows instead of packets
def combineFlows(flows, flowgap, bin_width, ipt_bin_width):
	if len(flows) == 0:
		return None

	outputflows = []

	flows.sort(key = lambda flow:flow.getStart())
	flows.sort(key = lambda flow:flow.key)
	
	# quantize the flowgap according to ipt_bin_width
	flowgap	= flowgap # // ipt_bin_width

	nextoutflow = Flow(None, bin_width, ipt_bin_width)
	for nextflow in flows:
		if (nextoutflow.key != nextflow.key) or ((nextflow.getStart() - nextoutflow.getEnd()) > flowgap):
			nextoutflow = nextflow
			outputflows.append(nextoutflow)
		else:
			nextoutflow.addFlow(nextflow)

	return outputflows

def getCustomWeightedAvg(n1, w1, n2, w2):
	num = 0
	den = 0
	if w1 > 0:
		num += w1 * n1
		den += w1
	if w2 > 0:
		num += w2 * n2
		den	+= w2
	if den <= 0:
		den = 1
	return num / den	


#write list of flows into file in desired format
def writeFlowsToFile(flowlist, filename):
	outfile = open(filename, 'w')
	
	to_write = []
	for flow in flowlist:
		# pl_flow_marker_str = ",".join([str(this_bin_count) for this_bin, this_bin_count in flow.pl_flow_marker.items()])
		# ipt_flow_marker_str = ",".join([str(this_bin_count) for this_bin, this_bin_count in flow.ipt_flow_marker.items()])
		pl_flow_marker_str, ipt_flow_marker_str = flow.getFlowMarkersAsCommaSeparatedStrings()
		to_write.append(
			socket.inet_ntoa(flow.ip1) + ',' +
			socket.inet_ntoa(flow.ip2) + ',' +
			str(flow.n_packet1) + ',' +
			str(flow.n_byte1) + ',' +
			'%.6f'%flow.t_start1 + ',' +
			'%.6f'%flow.t_end1 + ',' +
			'%.6f'%flow.getInterArrivaltime1() + ',' + 
			str(flow.n_packet2) + ',' +
			str(flow.n_byte2) + ',' +
			'%.6f'%flow.t_start2 + ',' +
			'%.6f'%flow.t_end2 + ',' +
			'%.6f'%flow.getInterArrivaltime2() + ',' +
			pl_flow_marker_str + ',' +
			ipt_flow_marker_str
			)
	
	outfile.write("\n".join(to_write))
	outfile.close()

#class which defines the structure of flows
class Flow:
	#constructor of default flow
	def __init__(self, firstpacket, bin_width, ipt_bin_width):
		global MAX_MTU, MAX_IPT
		# initialize the parameters for this flow's flow marker
		self.bin_width = bin_width
		self.ipt_bin_width = ipt_bin_width
		self.quantized_pl_bin_upper_limit = MAX_MTU // self.bin_width
		self.quantized_ipt_bin_upper_limit = MAX_IPT // self.ipt_bin_width
		self.pl_flow_marker = {key: 0 for key in range(1, self.quantized_pl_bin_upper_limit + 1)}
		self.ipt_flow_marker = {key: 0 for key in range(1, self.quantized_ipt_bin_upper_limit + 1)}

		if firstpacket == None:
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
			# first packet in a flow must update the flow marker
			if firstpacket.source < firstpacket.dest:
				self.ip1 = firstpacket.source
				self.ip2 = firstpacket.dest
				self.n_packet1 = 1
				self.n_byte1 = firstpacket.size
				self.t_start1 = firstpacket.timestamp
				self.t_end1 = firstpacket.timestamp
				self.t_interarrival1 = []						
				self.n_packet2 = 0
				self.n_byte2 = 0	
				self.t_start2 = 0
				self.t_end2 = 0
				self.t_interarrival2 = []
			else:
				self.ip1 = firstpacket.dest
				self.ip2 = firstpacket.source
				self.n_packet1 = 0
				self.n_byte1 = 0
				self.t_start1 = 0
				self.t_end1 = 0
				self.t_interarrival1 = []
				self.n_packet2 = 1
				self.n_byte2 = firstpacket.size				
				self.t_start2 = firstpacket.timestamp
				self.t_end2 = firstpacket.timestamp
				self.t_interarrival2 = []			

			self.key = firstpacket.key

			# UPDATE the flow markers using size and ipt of this packet
			self.update_flow_markers(firstpacket.size, firstpacket.timestamp)

	def update_flow_markers(self, pkt_size, pkt_timestamp):
		# the correct quantization bins for PL and IPT
		# quantization was done one level above this function call, so we don't do that here again!
		quantized_pl = int(pkt_size) 							# // self.bin_width
		quantized_ipt = int(pkt_timestamp - self.getEnd()) 		# // self.ipt_bin_width

		# UPDATE the PL flow marker while handling edge cases (less and greater than limits)
		if quantized_pl < 1:
			self.pl_flow_marker[1] += 1
		elif quantized_pl > self.quantized_pl_bin_upper_limit:
			self.pl_flow_marker[self.quantized_pl_bin_upper_limit] += 1
		else:
			self.pl_flow_marker[quantized_pl] += 1

		# print("quantized IPT = {0}".format(quantized_ipt))
		# UPDATE the IPT flow marker while handling edge cases (less and greater than limits)
		if quantized_ipt < 1:
			self.ipt_flow_marker[1] += 1
		elif quantized_ipt > self.quantized_ipt_bin_upper_limit:
			self.ipt_flow_marker[self.quantized_ipt_bin_upper_limit] += 1
		else:
			self.ipt_flow_marker[quantized_ipt] += 1

	#add a flow to the current flow (by changing volume and duration)
	def addFlow(self, flow):
		self.t_interarrival1 += flow.t_interarrival1
		self.t_interarrival2 += flow.t_interarrival2
		self.n_packet1 += flow.n_packet1
		self.n_packet2 += flow.n_packet2
		self.n_byte1 += flow.n_byte1
		self.n_byte2 += flow.n_byte2
				
		temp = min(self.t_start1,flow.t_start1)
		if temp == 0:
			self.t_start1 = self.t_start1 + flow.t_start1
		else:
			self.t_start1 = temp
		
		temp = min(self.t_start2,flow.t_start2)
		if temp == 0:
			self.t_start2 = self.t_start2 + flow.t_start2
		else:
			self.t_start2 = temp
		
		if(self.t_end1 < flow.t_end1):
			self.t_end1 = flow.t_end1
		if(self.t_end2 < flow.t_end2):
			self.t_end2 = flow.t_end2
		
		# ADD their PL flow markers
		for this_bin, this_bin_value in self.pl_flow_marker.items():
			self.pl_flow_marker[this_bin] = this_bin_value + flow.pl_flow_marker[this_bin]
		
		# ADD their IPT flow markers
		for this_bin, this_bin_value in self.ipt_flow_marker.items():
			self.ipt_flow_marker[this_bin] = this_bin_value + flow.ipt_flow_marker[this_bin]
	
	#add a packet to the current flow (by changing volume and duration)
	def addPacket(self, packet):
		
		if packet.source == self.ip1 and packet.dest == self.ip2:			
			
			# UPDATE the flow markers before updating flow end time
			self.update_flow_markers(packet.size, packet.timestamp)

			#initialize flow if not initialized
			if self.n_packet1 == 0:
				self.t_start1 = packet.timestamp
				self.t_end1 = packet.timestamp
				self.n_packet1 += 1
				self.n_byte1 += packet.size
				return

			if self.t_end1 < packet.timestamp:
				self.t_interarrival1.append(packet.timestamp-self.t_end1)
				self.t_end1 = packet.timestamp
			elif self.t_start1 > packet.timestamp:
				self.t_interarrival1.append(self.t_start1-packet.timestamp)
				self.t_start1 = packet.timestamp
			self.n_packet1 += 1
			self.n_byte1 += packet.size			
		
		elif packet.source == self.ip2 and packet.dest == self.ip1:
			
			# UPDATE the flow markers before updating flow end time
			self.update_flow_markers(packet.size, packet.timestamp)

			#initialize flow if not initialized
			if self.n_packet2 == 0:
				self.t_start2 = packet.timestamp
				self.t_end2 = packet.timestamp
				self.n_packet2 += 1
				self.n_byte2 += packet.size
				return
			
			if self.t_end2 < packet.timestamp:
				self.t_interarrival2.append(packet.timestamp-self.t_end2)
				self.t_end2 = packet.timestamp
			elif self.t_start2 > packet.timestamp:
				self.t_interarrival2.append(self.t_start2-packet.timestamp)
				self.t_start2 = packet.timestamp
			self.n_packet2 += 1
			self.n_byte2 += packet.size

		else:
			raise Exception('packet does not belong to flow')
	
	def getDurationInSeconds(self):
		return self.getEnd() - self.getStart()

	def getInterArrivaltime(self):
		combined = (self.t_interarrival1+self.t_interarrival2).sort()
		if len(combined) > 0:
			return combined[len(combined)//2]
		return 0	
	
	def getInterArrivaltime1(self):
		self.t_interarrival1.sort()
		if len(self.t_interarrival1) > 0:
			return self.t_interarrival1[len(self.t_interarrival1)//2]
		return 0

	def getInterArrivaltime2(self):
		self.t_interarrival2.sort()
		if len(self.t_interarrival2) > 0:
			return self.t_interarrival2[len(self.t_interarrival2)//2]
		return 0	
	
	def getNoOfBytes(self):
		return self.n_byte1 + self.n_byte2

	def getNoOfPackets(self):
		return self.n_packet1 + self.n_packet2

	def getStart(self):
		temp =  min(self.t_start1, self.t_start2)
		if temp == 0:
			return self.t_start1 + self.t_start2
		else:
			return temp

	def getEnd(self):
		return max(self.t_end1, self.t_end2)

	def getFlowMarkersAsCommaSeparatedStrings(self):
		pl_flow_marker_str = ",".join([str(this_bin_count) for this_bin, this_bin_count in self.pl_flow_marker.items()])
		ipt_flow_marker_str = ",".join([str(this_bin_count) for this_bin, this_bin_count in self.ipt_flow_marker.items()])
		return (pl_flow_marker_str, ipt_flow_marker_str)