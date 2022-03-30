from peershark.createTrainingData import runTrainingDataGenerator
from peershark.generateSuperFlows import runGenerateSuperFlows
from peershark.GenerateFlows import runGenerateFlows
from quantize import QuantizeDataset

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from joblib import dump, load

import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

import multiprocessing as MP
import subprocess as sub
import numpy as np
import argparse
import shutil
import time
import math
import sys
import csv
import gc
import os


def Classify(parentdir, training_data_dir, binWidth, ipt_bin_width):
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
				attributes.append(row[:-1])
				labels.append(row[-1])
		
		#Split data in 66% train, 33% test
		train_x, test_x, train_y, test_y = train_test_split(attributes, labels, test_size=0.33, random_state=42, stratify=labels)

		#Define classifier
		classifier = RandomForestClassifier(random_state=42)

		#Train classifier
		#start_train = time.time()
		model = classifier.fit(np.asarray(train_x), np.asarray(train_y))
		#end_train = time.time()
		#print("Model trained in %ss"%(end_train-start_train))

		#for sample in test_x:
		#	start_sample = time.time()
		#	model.predict(np.asarray(sample).reshape((1,-1)))
		#	end_sample = time.time()
		#	print("Sample predicted in %ss"%(end_sample-start_sample))
		
		#Perform predictions
		print("Predicting {0} samples".format(len(test_x)))
		#start_batch = time.time()
		predictions = model.predict(np.asarray(test_x))
		#end_batch = time.time()
		#print("Batch predicted in %ss"%(end_batch-start_batch))

		#Generate metrics (benign)
		TN, FP, FN, TP = confusion_matrix(np.asarray(test_y), predictions, labels=["malicious","benign"]).ravel()
		FPR_BENIGN = float(FP)/(float(FP)+float(TN))
		RECALL_BENIGN = float(TP)/(float(TP) + float(FN))
		PRECISION_BENIGN = float(TP)/(float(TP) + float(FP))

		print("Model Precision (benign): " + "{0:.3f}".format(PRECISION_BENIGN))
		print("Model Recall (benign): " + "{0:.3f}".format(RECALL_BENIGN))
		print("Model FPR (benign): " + "{0:.3f}".format(FPR_BENIGN))
		

		#Generate metrics (malicious)
		TN, FP, FN, TP = confusion_matrix(np.asarray(test_y), predictions, labels=["benign","malicious"]).ravel()
		FPR_MALICIOUS = float(FP)/(float(FP)+float(TN))
		RECALL_MALICIOUS = float(TP)/(float(TP) + float(FN))
		PRECISION_MALICIOUS = float(TP)/(float(TP) + float(FP))

		print("Model Precision (malicious): " + "{0:.3f}".format(PRECISION_MALICIOUS))
		print("Model Recall (malicious): " + "{0:.3f}".format(RECALL_MALICIOUS))
		print("Model FPR (malicious): " + "{0:.3f}".format(FPR_MALICIOUS))

		results_file = open(os.path.join(parentdir, "classificationResults", "results.csv"), "a")
		results_file.write("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}\n".format(
																			binWidth, 
																			ipt_bin_width, 
																			"{0:.3f}".format(PRECISION_BENIGN), 
																			"{0:.3f}".format(RECALL_BENIGN), 
																			"{0:.3f}".format(FPR_BENIGN), 
																			"{0:.3f}".format(PRECISION_MALICIOUS), 
																			"{0:.3f}".format(RECALL_MALICIOUS), 
																			"{0:.3f}".format(FPR_MALICIOUS)
																			))
		results_file.flush()
		results_file.close()
		print("")


def GenerateDataset(datasets, training_data_dir, binWidth, ipt_bin_width):
	if not os.path.exists(os.path.join(training_data_dir, 'Datasets')):
		os.makedirs(os.path.join(training_data_dir, 'Datasets'))
	
	datasets_to_merge = []
	for dataset in datasets:
		dataset = os.path.basename(dataset)
		datasets_to_merge.append(os.path.join(training_data_dir, dataset, 'trainingdata_{0}_{1}.csv'.format(binWidth, ipt_bin_width)))

	#Merge datasets in a single file
	with open(os.path.join(training_data_dir, 'Datasets', 'Dataset_{0}_{1}.csv'.format(binWidth, ipt_bin_width)), "w") as out_dataset:
		out_dataset.write("NumberOfPackets,TotalBytesTransmitted,MedianIPT,ConversationDuration,class\n")
		for fname in datasets_to_merge:
			with open(fname) as infile:
				csv_reader = csv.reader(infile)
				for row in csv_reader:
					new_row = row
					if(row[4] == "P2PTraffic"):
						new_row[4] = "benign"
					else:
						new_row[4] = "malicious"
					out_dataset.write(",".join(new_row) + "\n")


def RunPeerShark(quantized_pcap_data_dir, flow_data_dir, super_flow_data_dir, training_data_dir, bin_width, ipt_bin_width):
	# Set TIMEGAP
	timegap = 2000
	print("Generating Flows with TIMEGAP = {0}".format(timegap))
	runGenerateFlows(quantized_pcap_data_dir, flow_data_dir, timegap, bin_width, ipt_bin_width)
	# Set FLOWGAP in seconds
	flowgap = 3600
	print("Generating SuperFlows with FLOWGAP = {0}".format(flowgap))
	runGenerateSuperFlows(flow_data_dir, super_flow_data_dir, flowgap, bin_width, ipt_bin_width)
	print("Generating Training Data...")
	runTrainingDataGenerator(super_flow_data_dir, training_data_dir, bin_width, ipt_bin_width)


def Experiment(parentdir, datasets, bin_width, ipt_bin_width, do_cleanup):
	featuresets_dir 	= os.path.join(parentdir, 'FeatureSets')
	flow_data_dir 		= os.path.join(parentdir, 'FlowData')
	superflow_data_dir 	= os.path.join(parentdir, 'SuperFlowData')
	training_data_dir 	= os.path.join(parentdir, 'TrainingData')

	if not os.path.exists(featuresets_dir):
		os.makedirs(featuresets_dir)
	
	#Quantize datasets according to bin width
	#Generate training sets for quantization
	for dataset in datasets:
		quantized_pcap_dataset_dir 	= os.path.join(featuresets_dir, os.path.basename(dataset))
		flow_dataset_dir 			= os.path.join(flow_data_dir, os.path.basename(dataset))
		superflow_dataset_dir 		= os.path.join(superflow_data_dir, os.path.basename(dataset))
		training_dataset_dir 		= os.path.join(training_data_dir, os.path.basename(dataset))

		if not os.path.exists(quantized_pcap_dataset_dir):
			os.makedirs(quantized_pcap_dataset_dir)
		
		if not os.path.exists(flow_dataset_dir):
			os.makedirs(flow_dataset_dir)
		
		if not os.path.exists(superflow_dataset_dir):
			os.makedirs(superflow_dataset_dir)
		
		if not os.path.exists(training_dataset_dir):
			os.makedirs(training_dataset_dir)

		print(">> Quantizing {0} with BinWidth = {1} and IPT_BinWidth = {2}".format(dataset, bin_width, ipt_bin_width))
		QuantizeDataset(dataset, quantized_pcap_dataset_dir, bin_width, ipt_bin_width)
		RunPeerShark(quantized_pcap_dataset_dir, flow_dataset_dir, superflow_dataset_dir, training_dataset_dir, bin_width, ipt_bin_width)

	print("################################################################################################################################################")
	print("Building Dataset...")
	GenerateDataset(datasets, training_data_dir, bin_width, ipt_bin_width)
	print("################################################################################################################################################")	
	print("Performing Classification...")
	Classify(parentdir, training_data_dir, bin_width, ipt_bin_width)
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

	

