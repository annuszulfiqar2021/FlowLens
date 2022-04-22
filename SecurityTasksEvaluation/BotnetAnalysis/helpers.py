import random
import csv
import sys
import os


def GetPerPktHistSubsetFromFile(this_file_path, num_samples):
    attributes = []
    print("Reading {0} for per-packet histogram samples".format(this_file_path))
    with open(this_file_path) as this_file:
        all_rows = csv.reader(this_file)
        these_rows = random.sample(list(all_rows), num_samples)
    return these_rows


def getSubsetDataset(per_pkt_hist_dir, training_data_dir, binWidth, ipt_bin_width):
    dataset_dirs = [
        os.path.join(per_pkt_hist_dir, "P2PTraffic"),
        os.path.join(per_pkt_hist_dir, "Storm"),
        os.path.join(per_pkt_hist_dir, "Waledac")
    ]

    per_pkt_test = []
    for i, dataset in enumerate(dataset_dirs):
        # if i >= 2:
        #     continue
        NUM_SAMPLES_PER_FILE = 10000
        if os.path.basename(dataset) != "P2PTraffic":
            NUM_SAMPLES_PER_FILE = 24000
        print(os.path.basename(dataset))

        perPktHistCSV = [os.path.join(dataset, hist_csv) for hist_csv in os.listdir(dataset)]
        for j, PktHistCSV in enumerate(perPktHistCSV):
            # if j >= 2:
            #     continue
            # get the dataset from just this one file
            per_pkt_test += GetPerPktHistSubsetFromFile(PktHistCSV, NUM_SAMPLES_PER_FILE)
    
    # print(per_pkt_test)
    subset_testset_path = os.path.join(training_data_dir, 'Datasets', 'PerPktHist_Subset10k_24k_{0}_{1}.csv'.format(binWidth, ipt_bin_width))
    with open(subset_testset_path, "w", newline="") as this_file:
        writer = csv.writer(this_file)
        writer.writerows(per_pkt_test)

def makeLUTsFromModel(layers, lut_dir):
    for idx, layer_params in enumerate(layers):
        # layer_params = layer.get_weights()
        makeDNNWeightFile(layer_params, lut_dir, "L" + str(idx))
        makeDNNBiasFile(layer_params, lut_dir, "L" + str(idx))


def makeDNNWeightFile(layer_params, lut_dir, prefix):
    weight_file = lut_dir + "/" + prefix + "_NEURON_W_LUT" + ".csv"
    weights = layer_params[0]
    weights = weights.transpose([1, 0])
    write2DCSV(weight_file, weights)


def makeDNNBiasFile(layer_params, lut_dir, prefix):
    bias_file = lut_dir + "/" + prefix + "_NEURON_B_LUT" + ".csv"
    bias = layer_params[1]
    bias = bias.reshape(-1, len(bias)).transpose([1, 0])
    write2DCSV(bias_file, bias)


def write2DCSV(filename, matrix2D):
    with open(filename, 'w+') as csvfile:
        spamwriter = csv.writer(csvfile, delimiter=",", quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for arr in matrix2D:
            row = []
            for elem in arr:
                row.append(str(elem))
            spamwriter.writerow(row)


if __name__ == "__main__":
    per_pkt_hist_dir = "/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/PerPacketHistograms"
    training_data_dir = "/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/TrainingData/"
    getSubsetDataset(per_pkt_hist_dir, training_data_dir, 64, 512)