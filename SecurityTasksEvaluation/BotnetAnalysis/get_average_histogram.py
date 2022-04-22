import matplotlib.pyplot as plt
import numpy as np
import csv
import os

# PL_HIST_LENGTH = 46
# IPT_HIST_LENGTH = 56
PL_HIST_LENGTH = 23
IPT_HIST_LENGTH = 7

def get_average_histograms(training_data_dir, binWidth, ipt_bin_width):
    dataset_path = os.path.join(training_data_dir, 'Datasets', 'Dataset_{0}_{1}.csv'.format(binWidth, ipt_bin_width))
    with open(dataset_path) as dataset_file:
        print("Loading Dataset: {0} ...".format(dataset_path))
        benign_pl_attributes, benign_ipt_attributes = [], []
        malicious_pl_attributes, malicious_ipt_attributes = [], []
        csv_reader = csv.reader(dataset_file)
        for n, row in enumerate(csv_reader):
            if(n == 0):
                continue
            else:
                # only pick the bin attributes, not the high-level flow attributes
                # attributes.append(row[:-1])
                # attributes.append(row[4:-1])
                label = row[-1]
                pl_attribute = list(map(int, row[4:4+PL_HIST_LENGTH]))
                ipt_attribute = list(map(int, row[4+PL_HIST_LENGTH:-1]))
                if label == "benign":
                    benign_pl_attributes.append(pl_attribute) # pick only packet size bin fields
                    benign_ipt_attributes.append(ipt_attribute) # pick only packet length bin fields
                elif label == "malicious":
                    malicious_pl_attributes.append(pl_attribute)
                    malicious_ipt_attributes.append(ipt_attribute) # pick only packet length bin fields
                else:
                    print("UNKNOWN LABEL ({0}) FOUND!!".format(label))
    
    print("Benign attribute count = {0}".format(len(benign_pl_attributes)))
    print("Malicious attribute count = {0}".format(len(malicious_pl_attributes)))
    
    benign_pl_average_flowmarker = np.average(np.array(benign_pl_attributes), axis=0).tolist()
    malicious_pl_average_flowmarker = np.average(np.array(malicious_pl_attributes), axis=0).tolist()
    print("Benign PL Average FlowMarker = {0}".format(",".join(["{:.2f}".format(x) for x in benign_pl_average_flowmarker])))
    print("Malicious PL Average FlowMarker = {0}".format(",".join(["{:.2f}".format(x) for x in malicious_pl_average_flowmarker])))
    
    benign_ipt_average_flowmarker = np.average(np.array(benign_ipt_attributes), axis=0).tolist()
    malicious_ipt_average_flowmarker = np.average(np.array(malicious_ipt_attributes), axis=0).tolist()
    print("Benign IPT Average FlowMarker = {0}".format(",".join(["{:.2f}".format(x) for x in benign_ipt_average_flowmarker])))
    print("Malicious IPT Average FlowMarker = {0}".format(",".join(["{:.2f}".format(x) for x in malicious_ipt_average_flowmarker])))
    
    fig, axis = plt.subplots(3, 2)
    fig.set_figwidth(10)
    fig.set_figheight(10)
    # fig.ylim(-1, 50)
    # fig.suptitle('Average Histograms')
    axis[0, 0].plot(range(1, PL_HIST_LENGTH+1), benign_pl_average_flowmarker, "-.r")
    axis[0, 0].set_title("Benign PL Average Flow Marker")
    axis[1, 0].plot(range(1, PL_HIST_LENGTH+1), malicious_pl_average_flowmarker, ":b")
    axis[1, 0].set_title("Malicious PL Average Flow Marker")

    axis[0, 1].set_ylim([-0.1, 2])
    axis[0, 1].plot(range(1, IPT_HIST_LENGTH+1), benign_ipt_average_flowmarker, "-.r")
    axis[0, 1].set_title("Benign IPT Average Flow Marker")
    axis[1, 1].set_ylim([-0.1, 2])
    axis[1, 1].plot(range(1, IPT_HIST_LENGTH+1), malicious_ipt_average_flowmarker, ":b")
    axis[1, 1].set_title("Malicious IPT Average Flow Marker")

    axis[2, 0].set_ylim([-0.1, 2])
    axis[2, 0].set_title("PL Comparison")
    axis[2, 0].plot(range(1, PL_HIST_LENGTH+1), benign_pl_average_flowmarker, "-.r", label="Benign PL Average Flow Marker")
    axis[2, 0].plot(range(1, PL_HIST_LENGTH+1), malicious_pl_average_flowmarker, ":b", label="Malicious PL Average Flow Marker")
    axis[2, 1].set_ylim([-0.1, 2])
    axis[2, 1].set_title("IPT Comparison")
    axis[2, 1].plot(range(1, IPT_HIST_LENGTH+1), benign_ipt_average_flowmarker, "-.r", label="Benign IPT Average Flow Marker")
    axis[2, 1].plot(range(1, IPT_HIST_LENGTH+1), malicious_ipt_average_flowmarker, ":b", label="Malicious IPT Average Flow Marker")
    plt.savefig('average_histograms_{0}_{1}.png'.format(binWidth, ipt_bin_width), dpi=100)
    
    # # set y-axis limit for better comparitive view
    # plt.ylim(-1, 10)
    # plt.plot(range(1, 43), benign_pl_average_flowmarker, label="Benign Average Flow Marker", linestyle="-.")
    # plt.plot(range(1, 43), malicious_pl_average_flowmarker, label="Malicious Average Flow Marker", linestyle=":")
    # plt.savefig('average_histograms.png')


if __name__ == "__main__":
    # binWidth, ipt_bin_width = 32, 64
    binWidth, ipt_bin_width = 64, 512
    training_data_dir = "/home/taurus/botnet-detection/FlowLens/SecurityTasksEvaluation/BotnetAnalysis/TrainingData/"
    get_average_histograms(training_data_dir, binWidth, ipt_bin_width)