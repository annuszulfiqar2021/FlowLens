import os

PCAPDATADIR 		= '/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/Data/'
PCAPFILES 			= '/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/peershark/PcapInputFiles.txt'
TSHARKOPTIONSFILE 	= '/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/peershark/TsharkOptions.txt'
TCP_PROTO 			= '6'
UDP_PROTO 			= '17'
UDP_HEADERLENGTH 	= 8

# some parameters to limit flow characteristics
MAX_MTU = 1500
MAX_IPT = 3600

#utility functions
def getCSVFiles(dirname):
	csvfiles = []
	for eachfile in os.listdir(dirname):
		if eachfile.endswith('.csv'):
			csvfiles.append(os.path.join(dirname, eachfile))
	# get class label of these files 
	class_label = "benign"
	if(os.path.basename(dirname) == "Storm" or os.path.basename(dirname) == "Waledac"):
		class_label = "malicious"
	return csvfiles, class_label