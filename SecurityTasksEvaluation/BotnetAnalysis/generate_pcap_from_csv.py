from scapy.packet import Packet
from sklearn import metrics
import subprocess as sp
from scapy.all import *
import numpy as np
import argparse
import codecs
import time
import csv
import sys

PKT_LABELS = {
    "benign": 0,
    "malicious": 1
}


def makePayload(fields, types):
    ba = bytearray()
    for item in zip(fields, types):
        arr = bytearray()
        fld = item[0]
        typ = item[1]
        if typ == "float":
            arr = bytearray(struct.pack("f", fld))
        elif typ == "int":
            arr = bytearray(struct.pack("i", fld))
        elif typ == "fix16":
            #num = int(fld) << 16
            num = int(fld) << 0
            arr = bytearray(struct.pack("!i", num))
        elif typ == "byte":       
            arr = bytearray(struct.pack("b", int(fld)))
        ba = ba + arr
    return ba


def buildPkt(mac, ip, fields, types):
    # print(fields)
    payload = makePayload(fields, types)
    #return Ether(dst="00:00:00:ED:04:01", src="00:00:00:ED:03:01")/IP(dst="10.1.0.4", src="10.1.0.3", proto=253)/Raw(load=payload)
    return Ether(dst=mac[1], src=mac[0])/IP(dst=ip[1], src=ip[0], proto=253)/Raw(load=payload)


def load_csv(dataset):
    attributes, labels = [], []
    with open(dataset, newline='\n') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',')
        for i, row in enumerate(spamreader):
            if i == 0:
                # drop the header row
                continue
            pkt_attributes = list(map(int, row[4:-1]))
            pkt_label = PKT_LABELS[row[-1]]
            attributes.append(pkt_attributes)
            labels.append(pkt_label)
    return attributes, labels


def genIP():
    ip = str(random.randint(0,255))
    for i in range(3):
        new_int = random.randint(0,255)
        octet = str(new_int)
        ip = ip + "." + octet
    return ip


def genMAC():
    mac = '{:02X}'.format(random.randint(0,255))
    for i in range(5):
        new_int = random.randint(0,255)
        octet = '{:02X}'.format(new_int)
        mac = mac + ":" + octet
    return mac


def make_pcap(filename, attributes, labels):
    writer = PcapWriter(filename)
    mac = ["00:00:00:ED:03:01", "00:00:00:ED:04:01"]
    ip = ["10.1.0.3", "10.1.0.4"]
    types = ["fix16"] * len(attributes[0]) + ["byte", "byte"]
    print(len(types), types)
    pkts = []
    for i in range(len(attributes)):
        features = attributes[i] + [labels[i], 0] # this is ground-truth + one byte for prediction
        pkt = buildPkt(mac, ip, features, types)
        # print(len(pkt))
        pkts.append(pkt)
    writer.write(pkts)


def read_pcap(filename):
    reader = PcapReader(filename)
    pkts = []
    for pkt in reader:
        pkts.append(pkt)
        #print(hexdump(pkt))
    return pkts


def interpretPayload(payload):
    tup = struct.unpack("bb", payload.load[-2:])
    label = int(tup[0])
    prediction = int(tup[1])
    return label, prediction


def get_metrics(true_labels, predicted_labels, labels):
    accuracy = 100*metrics.accuracy_score(true_labels, predicted_labels)
    precision = 100*metrics.precision_score(true_labels, predicted_labels, average="weighted", labels=np.unique(predicted_labels))
    recall = 100*metrics.recall_score(true_labels, predicted_labels, average="weighted")
    f1 = 100*metrics.f1_score(true_labels, predicted_labels, average="weighted", labels=np.unique(predicted_labels))
    print("Accuracy: ", str(accuracy))
    print("Precision: ", str(precision))
    print("Recall: ", str(recall))
    print("F1-Score: ", str(f1))
    tn, fpo, fn, tp = metrics.confusion_matrix(true_labels, predicted_labels, labels=labels).ravel()
    print("TN ", str(tn))
    print("FP: ", str(fpo))
    print("FN: ", str(fn))
    print("TP: ", str(tp))
    return accuracy

def main(args):
    attributes, labels = load_csv(args["dataset"])
    make_pcap(args["output_file"], attributes, labels)


# test functions
if __name__ == "__main__":
    CLI = argparse.ArgumentParser()
    CLI.add_argument("--dataset", type=str)
    CLI.add_argument("--output_file", type=str)
    args = vars(CLI.parse_args())
    main(args)

    
