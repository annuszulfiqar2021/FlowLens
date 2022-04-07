from peershark.createTrainingData import runTrainingDataGenerator
from peershark.generateSuperFlows import runGenerateSuperFlows
from peershark.GenerateFlows import runGenerateFlows
from peershark.P2P_CONSTANTS import *
from quantize import QuantizeDataset

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from joblib import dump, load

import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

import multiprocessing as MP
import subprocess as sub
import numpy as np
import argparse
import shutil
import pickle
import random
import time
import math
import sys
import csv
import gc
import os


def GetPerPktHistDataset(perPacketHists_dir):

	saved_dataset_path = os.path.join(perPacketHists_dir, 'per_pkt_hist_dataset.pkl')
	if os.path.exists(saved_dataset_path):
		
		print("Pickled Dataset found. Reading now..")
		with open(saved_dataset_path, 'rb') as handle:
			per_pkt_hist_dataset = pickle.load(handle)
			attributes, labels = per_pkt_hist_dataset["attributes"], per_pkt_hist_dataset["labels"]

	else:
		print("Pickled Dataset not found. Regenerating now..")

		dataset_dirs = [
			os.path.join(perPacketHists_dir, "P2PTraffic"),
			os.path.join(perPacketHists_dir, "Storm"),
			os.path.join(perPacketHists_dir, "Waledac")
		]
		attributes, labels = [], []
		for dataset in dataset_dirs:
			print(dataset)
			print(os.path.basename(dataset))
			if os.path.basename(dataset) == "Waledac":
				perPktHistCSV = [os.path.join(dataset, hist_csv) for hist_csv in os.listdir(dataset)]
				for PktHistCSV in perPktHistCSV:
					print("Reading {0} for per-packet histogram samples".format(PktHistCSV))
					with open(PktHistCSV) as this_file:
						reader = csv.reader(this_file)
						# chosen_rows = random.sample(list(reader), 10000)
						chosen_rows = reader
						for row in chosen_rows:
							# only pick the bin attributes, not the high-level flow attributes
							attributes.append(row[:-1])
							labels.append(row[-1])

		# the dataset is too huge! No point of saving as pickle
		# with open(saved_dataset_path, 'wb') as handle:
		# 	per_pkt_hist_dataset = {
		# 		"attributes": attributes,
		# 		"labels": labels
		# 	}
		# 	pickle.dump(per_pkt_hist_dataset, handle, protocol=pickle.HIGHEST_PROTOCOL)

	#Split data in 0% train, 100% test
	_, test_x, _, test_y = train_test_split(attributes, labels, test_size=0.99, random_state=42, stratify=labels)
	return (test_x, test_y)


def GetPerPktHistDatasetFromFile(this_file_path):
	attributes = []
	labels = []
	print("Reading {0} for per-packet histogram samples".format(this_file_path))
	with open(this_file_path) as this_file:
		all_rows = csv.reader(this_file)
		for row in all_rows:
			# only pick the bin attributes, not the high-level flow attributes
			attributes.append(row[:-1])
			labels.append(row[-1])

	#Split data in 0% train, 100% test
	_, test_x, _, test_y = train_test_split(attributes, labels, test_size=0.99, random_state=42, stratify=labels)
	return (test_x, test_y)


def RunClassification(model, test_x, test_y):
	#Perform predictions
	print("Test_X size = {0}, Test_Y size = {1}".format(np.asarray(test_x).shape, np.asarray(test_y).shape))
	predictions = model.predict(np.asarray(test_x))
	#Generate metrics (benign)
	TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN = confusion_matrix(np.asarray(test_y), predictions, labels=["malicious","benign"]).ravel()
	#Generate metrics (malicious)
	TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS = confusion_matrix(np.asarray(test_y), predictions, labels=["benign","malicious"]).ravel()
	return ((TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN), (TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS))


def print_metrics(TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN, TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS):
	# get metrics for benign class
	FPR_BENIGN = float(FP_BENIGN)/(float(FP_BENIGN)+float(TN_BENIGN)) if (float(FP_BENIGN)+float(TN_BENIGN)) else 0
	RECALL_BENIGN = float(TP_BENIGN)/(float(TP_BENIGN) + float(FN_BENIGN)) if (float(TP_BENIGN) + float(FN_BENIGN)) else 0
	PRECISION_BENIGN = float(TP_BENIGN)/(float(TP_BENIGN) + float(FP_BENIGN)) if (float(TP_BENIGN) + float(FP_BENIGN)) else 0
	F1_BENIGN = 2*PRECISION_BENIGN*RECALL_BENIGN / (PRECISION_BENIGN+RECALL_BENIGN)

	print("Model Precision (benign): " + "{0:.3f}".format(PRECISION_BENIGN))
	print("Model Recall (benign): " + "{0:.3f}".format(RECALL_BENIGN))
	print("Model FPR (benign): " + "{0:.3f}".format(FPR_BENIGN))
	print("Model F1 Score (benign): " + "{0:.3f}".format(F1_BENIGN))

	FPR_MALICIOUS = float(FP_MALICIOUS)/(float(FP_MALICIOUS)+float(TN_MALICIOUS)) if (float(FP_MALICIOUS)+float(TN_MALICIOUS)) else 0
	RECALL_MALICIOUS = float(TP_MALICIOUS)/(float(TP_MALICIOUS) + float(FN_MALICIOUS)) if (float(TP_MALICIOUS) + float(FN_MALICIOUS)) else 0
	PRECISION_MALICIOUS = float(TP_MALICIOUS)/(float(TP_MALICIOUS) + float(FP_MALICIOUS)) if (float(TP_MALICIOUS) + float(FP_MALICIOUS)) else 0
	F1_MALICIOUS = 2*PRECISION_MALICIOUS*RECALL_MALICIOUS / (PRECISION_MALICIOUS+RECALL_MALICIOUS)

	print("Model Precision (malicious): " + "{0:.3f}".format(PRECISION_MALICIOUS))
	print("Model Recall (malicious): " + "{0:.3f}".format(RECALL_MALICIOUS))
	print("Model FPR (malicious): " + "{0:.3f}".format(FPR_MALICIOUS))
	print("Model F1 Score (malicious): " + "{0:.3f}".format(F1_MALICIOUS))
	print()


def Classify(parentdir, per_pkt_hist_dir, training_data_dir, binWidth, ipt_bin_width):
	dataset_path = os.path.join(training_data_dir, 'Datasets', 'Dataset_{0}_{1}.csv'.format(binWidth, ipt_bin_width))
	with open(dataset_path) as dataset_file:
		print("Loading Dataset: {0} ...".format(dataset_path))

		attributes = []
		labels = []
		csv_reader = csv.reader(dataset_file)
		for n, row in enumerate(csv_reader):
			if(n == 0):
				continue
			else:
				# only pick the bin attributes, not the high-level flow attributes
				# attributes.append(row[:-1])
				attributes.append(row[4:-1])
				labels.append(row[-1])
		
		#Split data in 66% train, 33% test
		train_x, test_x, train_y, test_y = train_test_split(attributes, labels, test_size=0.33, random_state=42, stratify=labels)

		print("Dataset size: Train_X = {0}, Train_Y = {1}, Test_X = {2}, Test_Y = {3}".format(np.asarray(train_x).shape, 
																								np.asarray(train_y).shape, 
																								np.asarray(test_x).shape, 
																								np.asarray(test_y).shape))

		#Define classifier
		# classifier = RandomForestClassifier(random_state=42)
		classifier = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(10, 10, 10, 10), random_state=1)

		#Train classifier
		model = classifier.fit(np.asarray(train_x), np.asarray(train_y))

		#Perform predictions
		((TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN), (TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS)) = RunClassification(model, test_x, test_y)

		# get metrics for benign/malicious class
		print_metrics(TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN, TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS)

		# results_file = open(os.path.join(parentdir, "classificationResults", "results.csv"), "a")
		# results_file.write("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}\n".format(
		# 																	binWidth, 
		# 																	ipt_bin_width, 
		# 																	"{0:.3f}".format(PRECISION_BENIGN), 
		# 																	"{0:.3f}".format(RECALL_BENIGN), 
		# 																	"{0:.3f}".format(FPR_BENIGN), 
		# 																	"{0:.3f}".format(PRECISION_MALICIOUS), 
		# 																	"{0:.3f}".format(RECALL_MALICIOUS), 
		# 																	"{0:.3f}".format(FPR_MALICIOUS)
		# 																	))
		# results_file.flush()
		# results_file.close()
		
		print("################################################################################################################################################")
		
		print("Reading per-packet histograms now..")
		#Perform predictions on per-packet histograms
		# per_pkt_test_x, per_pkt_test_y = GetPerPktHistDataset(per_pkt_hist_dir)

		dataset_dirs = [
			os.path.join(per_pkt_hist_dir, "P2PTraffic"),
			os.path.join(per_pkt_hist_dir, "Storm"),
			os.path.join(per_pkt_hist_dir, "Waledac")
		]
		attributes, labels = [], []
		
		# our net results will be in here
		total_per_packet_TN_BENIGN = 0
		total_per_packet_FP_BENIGN = 0
		total_per_packet_FN_BENIGN = 0
		total_per_packet_TP_BENIGN = 0
		total_per_packet_TN_MALICIOUS = 0
		total_per_packet_FP_MALICIOUS = 0 
		total_per_packet_FN_MALICIOUS = 0
		total_per_packet_TP_MALICIOUS = 0

		arguments = []
		# we will do inference over all files one by one
		for dataset in dataset_dirs:
			
			# print(dataset)
			# print("Processing {0}".format(os.path.basename(dataset)))
			perPktHistCSV = [os.path.join(dataset, hist_csv) for hist_csv in os.listdir(dataset)]
			for PktHistCSV in perPktHistCSV:
				# print("Reading {0} for {1}".format(PktHistCSV, os.path.basename(dataset)))
				# reset as a sanity check
				TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN = None, None, None, None
				TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS = None, None, None, None
				
				# get the dataset from just this one file
				per_pkt_test_x, per_pkt_test_y = GetPerPktHistDatasetFromFile(PktHistCSV)
				
				# append arguments for this prediction
				# arguments.append((model, per_pkt_test_x, per_pkt_test_y))

				# do prediction on this set
				(TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN), (TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS) = RunClassification(model, 
																																			per_pkt_test_x, 
																																			per_pkt_test_y)

				# print the metrics for this file
				print_metrics(TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN, TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS)

				# update our global counters
				total_per_packet_TN_BENIGN += TN_BENIGN
				total_per_packet_FP_BENIGN += FP_BENIGN
				total_per_packet_FN_BENIGN += FN_BENIGN
				total_per_packet_TP_BENIGN += TP_BENIGN
				total_per_packet_TN_MALICIOUS += TN_MALICIOUS
				total_per_packet_FP_MALICIOUS += FP_MALICIOUS 
				total_per_packet_FN_MALICIOUS += FN_MALICIOUS
				total_per_packet_TP_MALICIOUS += TP_MALICIOUS

				# print("Test_X size = {0}, Test_Y size = {1}".format(np.asarray(per_pkt_test_x).shape, np.asarray(per_pkt_test_y).shape))
				# predictions = model.predict(np.asarray(per_pkt_test_x))

				#Generate metrics (benign)
				# TN, FP, FN, TP = confusion_matrix(np.asarray(per_pkt_test_y), predictions, labels=["malicious","benign"]).ravel()
				# FPR_BENIGN = float(FP)/(float(FP)+float(TN)) if (float(FP)+float(TN)) else 0
				# RECALL_BENIGN = float(TP)/(float(TP) + float(FN)) if (float(TP) + float(FN)) else 0
				# PRECISION_BENIGN = float(TP)/(float(TP) + float(FP)) if (float(TP) + float(FP)) else 0

				# print("Per-Packet Model Precision (benign): " + "{0:.3f}".format(PRECISION_BENIGN))
				# print("Per-Packet Model Recall (benign): " + "{0:.3f}".format(RECALL_BENIGN))
				# print("Per-Packet Model FPR (benign): " + "{0:.3f}".format(FPR_BENIGN))
				
				#Generate metrics (malicious)
				# TN, FP, FN, TP = confusion_matrix(np.asarray(per_pkt_test_y), predictions, labels=["benign","malicious"]).ravel()
				# FPR_MALICIOUS = float(FP)/(float(FP)+float(TN)) if (float(FP)+float(TN)) else 0
				# RECALL_MALICIOUS = float(TP)/(float(TP) + float(FN)) if (float(TP) + float(FN)) else 0
				# PRECISION_MALICIOUS = float(TP)/(float(TP) + float(FP)) if (float(TP) + float(FP)) else 0

				# print("Per-Packet Model Precision (malicious): " + "{0:.3f}".format(PRECISION_MALICIOUS))
				# print("Per-Packet Model Recall (malicious): " + "{0:.3f}".format(RECALL_MALICIOUS))
				# print("Per-Packet Model FPR (malicious): " + "{0:.3f}".format(FPR_MALICIOUS))
				# print("")

		# # we are using a Pool to manage all our test sets in parallel
		# # spawn a pool of processes
		# print(f"Starting flow generation on 8 cores")
		# # https://zetcode.com/python/multiprocessing/
		# with MP.Pool(processes=8) as pool:
		# 	results = pool.starmap(RunClassification, arguments)

		# results should contain outputs for all predictions. We have to combine them
		# for ((TN_BENIGN, FP_BENIGN, FN_BENIGN, TP_BENIGN), (TN_MALICIOUS, FP_MALICIOUS, FN_MALICIOUS, TP_MALICIOUS)) in results:
		# 	# update our global counters
		# 	total_per_packet_TN_BENIGN += TN_BENIGN
		# 	total_per_packet_FP_BENIGN += FP_BENIGN
		# 	total_per_packet_FN_BENIGN += FN_BENIGN
		# 	total_per_packet_TP_BENIGN += TP_BENIGN
		# 	total_per_packet_TN_MALICIOUS += TN_MALICIOUS
		# 	total_per_packet_FP_MALICIOUS += FP_MALICIOUS 
		# 	total_per_packet_FN_MALICIOUS += FN_MALICIOUS
		# 	total_per_packet_TP_MALICIOUS += TP_MALICIOUS

		# get metrics for benign/malicious class
		print("Total Counts are as following:")
		print("total_per_packet_TN_BENIGN = {0}".format(total_per_packet_TN_BENIGN))
		print("total_per_packet_FP_BENIGN = {0}".format(total_per_packet_FP_BENIGN))
		print("total_per_packet_FN_BENIGN = {0}".format(total_per_packet_FN_BENIGN))
		print("total_per_packet_TP_BENIGN = {0}".format(total_per_packet_TP_BENIGN))
		print("total_per_packet_TN_MALICIOUS = {0}".format(total_per_packet_TN_MALICIOUS))
		print("total_per_packet_FP_MALICIOUS = {0}".format(total_per_packet_FP_MALICIOUS))
		print("total_per_packet_FN_MALICIOUS = {0}".format(total_per_packet_FN_MALICIOUS))
		print("total_per_packet_TP_MALICIOUS = {0}".format(total_per_packet_TP_MALICIOUS))
		print_metrics(total_per_packet_TN_BENIGN, total_per_packet_FP_BENIGN, total_per_packet_FN_BENIGN, total_per_packet_TP_BENIGN,
					total_per_packet_TN_MALICIOUS, total_per_packet_FP_MALICIOUS, total_per_packet_FN_MALICIOUS, total_per_packet_TP_MALICIOUS)


def GenerateDataset(datasets, training_data_dir, binWidth, ipt_bin_width):
	if not os.path.exists(os.path.join(training_data_dir, 'Datasets')):
		os.makedirs(os.path.join(training_data_dir, 'Datasets'))
	
	datasets_to_merge = []
	for dataset in datasets:
		dataset = os.path.basename(dataset)
		datasets_to_merge.append(os.path.join(training_data_dir, dataset, 'trainingdata_{0}_{1}.csv'.format(binWidth, ipt_bin_width)))

	#Merge datasets in a single file
	with open(os.path.join(training_data_dir, 'Datasets', 'Dataset_{0}_{1}.csv'.format(binWidth, ipt_bin_width)), "w") as out_dataset:
		# calculate correct index of class label
		quantized_pl_bin_upper_limit = MAX_MTU // binWidth
		quantized_ipt_bin_upper_limit = MAX_IPT // ipt_bin_width
		class_index = 4 + quantized_pl_bin_upper_limit + quantized_ipt_bin_upper_limit
		# include the flow marker labels in the csv header
		header_string = "NumberOfPackets,TotalBytesTransmitted,MedianIPT,ConversationDuration,"
		header_string += ','.join(['l{0}'.format(i) for i in range(1, quantized_pl_bin_upper_limit + 1)]) + ','
		header_string += ','.join(['i{0}'.format(j) for j in range(1, quantized_ipt_bin_upper_limit + 1)]) + ','
		header_string += "class\n"
		out_dataset.write(header_string)
		for fname in datasets_to_merge:
			with open(fname) as infile:
				csv_reader = csv.reader(infile)
				for row in csv_reader:
					new_row = row
					if(row[class_index] == "P2PTraffic"):
						new_row[class_index] = "benign"
					else:
						new_row[class_index] = "malicious"
					out_dataset.write(",".join(new_row) + "\n")


def RunPeerShark(quantized_pcap_data_dir, per_packet_hist_dataset_dir, flow_data_dir, super_flow_data_dir, training_data_dir, bin_width, ipt_bin_width):
	# Set TIMEGAP
	timegap = 2000
	print("Generating Flows with TIMEGAP = {0}".format(timegap))
	runGenerateFlows(quantized_pcap_data_dir, per_packet_hist_dataset_dir, flow_data_dir, timegap, bin_width, ipt_bin_width)
	# Set FLOWGAP in seconds
	flowgap = 3600
	print("Generating SuperFlows with FLOWGAP = {0}".format(flowgap))
	runGenerateSuperFlows(flow_data_dir, super_flow_data_dir, flowgap, bin_width, ipt_bin_width)
	print("Generating Training Data...")
	runTrainingDataGenerator(super_flow_data_dir, training_data_dir, bin_width, ipt_bin_width)


def Experiment(parentdir, datasets, bin_width, ipt_bin_width, do_cleanup):
	featuresets_dir 	= os.path.join(parentdir, 'FeatureSets')
	perPacketHists_dir 	= os.path.join(parentdir, 'PerPacketHistograms')
	flow_data_dir 		= os.path.join(parentdir, 'FlowData')
	superflow_data_dir 	= os.path.join(parentdir, 'SuperFlowData')
	training_data_dir 	= os.path.join(parentdir, 'TrainingData')

	if not os.path.exists(featuresets_dir):
		os.makedirs(featuresets_dir)
	
	if not os.path.exists(perPacketHists_dir):
		os.makedirs(perPacketHists_dir)

	#Quantize datasets according to bin width
	#Generate training sets for quantization
	for dataset in datasets:
		quantized_pcap_dataset_dir 	= os.path.join(featuresets_dir, os.path.basename(dataset))
		per_packet_hist_dataset_dir = os.path.join(perPacketHists_dir, os.path.basename(dataset))
		flow_dataset_dir 			= os.path.join(flow_data_dir, os.path.basename(dataset))
		superflow_dataset_dir 		= os.path.join(superflow_data_dir, os.path.basename(dataset))
		training_dataset_dir 		= os.path.join(training_data_dir, os.path.basename(dataset))

		all_exist = 0

		if not os.path.exists(quantized_pcap_dataset_dir):
			os.makedirs(quantized_pcap_dataset_dir)
		else:
			all_exist += 1
		
		if not os.path.exists(per_packet_hist_dataset_dir):
			os.makedirs(per_packet_hist_dataset_dir)
		else:
			all_exist += 1

		if not os.path.exists(flow_dataset_dir):
			os.makedirs(flow_dataset_dir)
		else:
			all_exist += 1

		if not os.path.exists(superflow_dataset_dir):
			os.makedirs(superflow_dataset_dir)
		else:
			all_exist += 1
		
		if not os.path.exists(training_dataset_dir):
			os.makedirs(training_dataset_dir)
		else:
			all_exist += 1
		
		if all_exist == 5:
			print("Quantization and processing already done for {0}. Moving to classification...".format(dataset))
			continue

		print(">> Quantizing and Generating Per-Packet Histograms {0} with BinWidth = {1} and IPT_BinWidth = {2}".format(dataset, bin_width, ipt_bin_width))
		QuantizeDataset(dataset, quantized_pcap_dataset_dir, bin_width, ipt_bin_width)
		RunPeerShark(quantized_pcap_dataset_dir, per_packet_hist_dataset_dir, flow_dataset_dir, superflow_dataset_dir, training_dataset_dir, bin_width, ipt_bin_width)

	print("################################################################################################################################################")
	if all_exist != 5:
		print("Building Dataset...")
		GenerateDataset(datasets, training_data_dir, bin_width, ipt_bin_width)
	print("################################################################################################################################################")	
	print(">> Starting Training...")
	Classify(parentdir, perPacketHists_dir, training_data_dir, bin_width, ipt_bin_width)
	print("################################################################################################################################################")	
	
	start_collect = time.time()
	collected = gc.collect()
	end_collect = time.time()
	print("Time wasted on GC - Classification: {0}s, collected {1} objects".format(end_collect-start_collect, collected))

	if do_cleanup:
		shutil.rmtree(featuresets_dir)
		shutil.rmtree(flow_data_dir)
		shutil.rmtree(superflow_data_dir)
		shutil.rmtree(training_data_dir)

def main(args):
	###
	#The following parameters are now fed by the fullRun.sh shell script
	# Please run fullRun.sh instead of this file directly
	###
	#Quantization (packet size)
	#BIN_WIDTH = [1, 16, 32, 64, 128, 256]

	#Quantization (IPT in seconds)
	#TIMEGAP IS 2000s, FLOWGAP IS 3600s
	#IPT_BIN_WIDTH = [0, 1, 10, 60, 300, 900]
	
	print(args)
	parent_dir = args["parentdir"]
	dataset_dir = os.path.join(parent_dir, "Data")
	dataset_dirs = [
		os.path.join(dataset_dir, "P2PTraffic"),
		os.path.join(dataset_dir, "Storm"),
		os.path.join(dataset_dir, "Waledac")
	]
	classification_dir = os.path.join(parent_dir, "classificationResults")
	if not os.path.exists(classification_dir):
		os.makedirs(classification_dir)
	results_file = open(os.path.join(classification_dir, "results.csv"), "a+") 
	results_file.write("BinWidth, IPT_BinWidth, Precision_Benign, Recall_Benign, FalsePositiveRate_Benign, Precision_Malicious, Recall_Malicious, FalsePositiveRate_Malicious\n")
	results_file.flush()
	results_file.close()
	
	print("Starting experiment with Bin width {0} and IPT Bin Width {1}".format(args["QL_PL"], args["QL_IPT"]))
	start_time = time.time()
	Experiment(parent_dir, dataset_dirs, args["QL_PL"], args["QL_IPT"], args["do_cleanup"])
	end_time = time.time()
	time_elapsed_seconds = end_time - start_time
	print("Experiment finished in {0:.2f}h\n".format(time_elapsed_seconds/60.0/60.0))


if __name__ == "__main__":
	CLI = argparse.ArgumentParser()
	CLI.add_argument("--parentdir", type=str)
	CLI.add_argument("--QL_PL", type=int)
	CLI.add_argument("--QL_IPT", type=int)
	CLI.add_argument("--do_cleanup", action='store_true')
	args = vars(CLI.parse_args())
	main(args)

	

