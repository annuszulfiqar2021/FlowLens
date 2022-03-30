from .P2P_CONSTANTS import *
from . import SuperFlow
from . import Flow
import socket
import sys
import os


def runGenerateSuperFlows(flow_data_dir, super_flow_data_dir, flowgap, bin_width, ipt_bin_width):
	#TIMEGAP IN SECONDS
	csvfiles = getCSVFiles(flow_data_dir)
	#print csvfiles

	flowdata = []
	for filename in csvfiles:
		inputfile = open(filename)
		data = [line.strip() for line in inputfile]
		inputfile.close()

		for eachline in data:
			fields = eachline.split(',')
			flowdata.append(SuperFlow.SuperFlow(fields, bin_width, ipt_bin_width))
	print('\tNo. of flows to be processed: ' + str(len(flowdata)))
	
	flowdata = Flow.combineFlows(flowdata, flowgap, bin_width, ipt_bin_width)
	print('\tSuperflows (Flows with flowgap = ' + str(flowgap) + ' sec) : ' + str(len(flowdata)))

	outfile = open(os.path.join(super_flow_data_dir, str(flowgap) + '.csv'), 'w')
	
	to_write = []
	for flow in flowdata:
		pl_flow_marker_str = ",".join([str(this_bin_count) for this_bin, this_bin_count in flow.pl_flow_marker.items()])
		ipt_flow_marker_str = ",".join([str(this_bin_count) for this_bin, this_bin_count in flow.ipt_flow_marker.items()])
		to_write.append(
			socket.inet_ntoa(flow.ip1) + ',' +
			socket.inet_ntoa(flow.ip2) + ',' +
			str(flow.getNoOfPackets()) + ',' +
			str(flow.getNoOfBytes()) + ',' +
			'%.6f'%flow.getInterArrivaltime() + ',' +
			'%.6f'%flow.getStart() + ',' +
			'%.6f'%flow.getEnd() + ',' +
			'%.6f'%flow.getDurationInSeconds() + ',' +
			pl_flow_marker_str + ',' +
			ipt_flow_marker_str)
	outfile.write("\n".join(to_write))
	outfile.close()