## Module to obtain packet data from a pcap/dump file
## and save it in csv format using tshark.
## Filenames of input pcap files are taken from InputFiles.txt
## Tshark options are present in TsharkOptions.txt
## TsharkOptions.txt should not contain the -r option.

## usage: python FilterPackets.py

#import global constants
from P2P_CONSTANTS import *
from FilterPacketsHelper import *
import multiprocessing as MP
import subprocess

#execute a shell command as a child process
def executeCommand(command, outfilename):
	print("Executing this command: {0}".format(command))
	subprocess.call(command, shell=True)
	infile = open(outfilename, 'r')
	data = [eachline.strip() for eachline in infile]
	infile.close()
	data = preprocess(data)
	outfile = open(outfilename,'w')
	for eachcomponent in data:
		outfile.write(eachcomponent)
	outfile.close()
	print('done processing : ' + outfilename)


if __name__ == "__main__":
	#obtain input parameters and pcapfilenames
	inputfiles = getPCapFileNames()
	print("Got {0} input pcap files".format(len(inputfiles)))
	# print("Input Files: " + str(inputfiles))
	tsharkOptions = getTsharkOptions()
	#get tshark commands to be executed
	arguments = []
	for filename in inputfiles:
		# print(filename)
		(command, outfilename) = contructTsharkCommand(filename,tsharkOptions)
		arguments.append((command, outfilename))
	# spawn a pool of processes
	print(f"Starting computation on {MP.cpu_count()} cores")
	# https://zetcode.com/python/multiprocessing/
	with MP.Pool() as pool:
		pool.starmap(executeCommand, arguments)