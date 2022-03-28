from .P2P_CONSTANTS import *
from .Packet import *
from .Flow import *
import multiprocessing as MP
import socket
import gc
import time

## module to read all the files in the data folder of the 
## project, build flow data and store it in a file


def generateFlow(filename, flow_data_dir, timegap):
	# sem.acquire()
	
	inputfile = open(filename)
	data = [line.strip() for line in inputfile]
	inputfile.close()
		
	packetlist = []
	for eachline in data:
		fields = eachline.split(',')
		fields.pop(2)
		packetlist.append(Packet(fields))
	
	outflowlist = packetsToFlows(packetlist, timegap)
	#print('flows in ' + filename + ' : ' + str(len(outflowlist)))
	
	outfilename = flow_data_dir + (filename.split('/')[-1])		
	writeFlowsToFile(outflowlist, outfilename)

	#print('done writing to : ' + outfilename)
	#start_collect = time.time()
	#collected = gc.collect()
	#end_collect = time.time()
	#print("Time wasted on GC - GenerateFlows: %ss, collected %s objects"%(end_collect-start_collect, collected))
	# sem.release()

def runGenerateFlows(quantized_pcap_data_dir, flow_data_dir, timegap):
	#create a semaphore so as not to exceed n_processes process limit
	csvfiles = getCSVFiles(quantized_pcap_data_dir)
	arguments = []
	#generate flowdata from each input packet file(not pcap) in parallel and store it in a file
	#so we get as many output files as number of input files
	for filename in csvfiles:
		arguments.append((filename, flow_data_dir, timegap))

	# print("Tasklist size = %s"%(len(tasklist)))

	# # #execute commands in parallel
	# for i in range(0, len(tasklist), n_processes):
	# 	for k,task in enumerate(tasklist[i:i+n_processes]):
	# 		tasklist[i+k].start()
	# 	for k, task in enumerate(tasklist[i:i+n_processes]):
	# 		tasklist[i+k].join()
	# 		#print("Joined task number %s"%(i+k))

	# spawn a pool of processes
	print(f"Starting flow generation on {MP.cpu_count()} cores")
	# https://zetcode.com/python/multiprocessing/
	with MP.Pool() as pool:
		pool.starmap(generateFlow, arguments)