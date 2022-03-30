from .P2P_CONSTANTS import *
import os


# some parameters to limit flow characteristics
MAX_MTU = 1500
MAX_IPT = 3600


def runTrainingDataGenerator(super_flow_data_dir, training_data_dir, bin_width, ipt_bin_width):
	#takes takes 50,000 examples and puts it in necessary format for training
	csvfiles = []
	if os.path.isdir(super_flow_data_dir):
		csvfiles += getCSVFiles(super_flow_data_dir)

	#print ".csv files to generate training data: %s"%(csvfiles)

	# initialize some parameters for flow marker
	quantized_pl_bin_upper_limit = MAX_MTU // bin_width
	quantized_ipt_bin_upper_limit = MAX_IPT // ipt_bin_width

	outfile = open(os.path.join(training_data_dir, 'trainingdata_' + str(bin_width) + "_" + str(ipt_bin_width) + '.csv'),'w')
	for filename in csvfiles:
		label = filename.split('/')[-2]
		inputfile = open(filename)
		line = inputfile.readline().strip()
		while line!='':
			fields = line.split(',')
			if float(fields[4])!=0 and float(fields[3])!=0 and float(fields[7])!=0:

				# READ flow markers from input fields
				# fields 0-11 are flow fields, 
				next_field = 12

				# onwards until self.quantized_pl_bin_upper_limit is the pl_flowmarker
				pl_flow_marker = {}
				for this_bin in range(1, quantized_pl_bin_upper_limit + 1):
					pl_flow_marker[this_bin] = int(fields[next_field])
					next_field += 1

				# then afterwards, all fields are self.quantized_ipt_bin_upper_limit
				ipt_flow_marker = {}
				for this_bin in range(1, quantized_ipt_bin_upper_limit + 1):
					ipt_flow_marker[this_bin] = int(fields[next_field])
					next_field += 1

				# convert the above flow markers to strings that we can write to csv
				pl_flow_marker_str = ",".join([str(this_bin_count) for this_bin, this_bin_count in pl_flow_marker.items()])
				ipt_flow_marker_str = ",".join([str(this_bin_count) for this_bin, this_bin_count in ipt_flow_marker.items()])

				outfile.write(
					fields[2] + ',' +
					fields[3] + ',' +
					fields[4] + ',' +
					fields[7] + ',' +
					pl_flow_marker_str + ',' + 
					ipt_flow_marker_str + ',' +
					label + '\n')
			line = inputfile.readline().strip()
		inputfile.close()
	outfile.close()