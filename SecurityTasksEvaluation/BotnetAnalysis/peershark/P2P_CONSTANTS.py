PCAPDATADIR 		= '/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/Data/'
PCAPFILES 			= '/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/peershark/PcapInputFiles.txt'
TSHARKOPTIONSFILE 	= '/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/peershark/TsharkOptions.txt'
TCP_PROTO 			= '6'
UDP_PROTO 			= '17'
UDP_HEADERLENGTH 	= 8

#utility functions
import os
def getCSVFiles(dirname):
	csvfiles = []
	for eachfile in os.listdir(dirname):
		if eachfile.endswith('.csv'):
			csvfiles.append(dirname + eachfile)	
	return csvfiles