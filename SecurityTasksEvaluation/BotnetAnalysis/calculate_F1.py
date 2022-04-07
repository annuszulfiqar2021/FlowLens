from runExperiment import print_metrics

def main():

    # This numbers are for Random Forest
    total_per_packet_TN_BENIGN = 48723573
    total_per_packet_FP_BENIGN = 11790518
    total_per_packet_FN_BENIGN = 606721
    total_per_packet_TP_BENIGN = 39023334
    total_per_packet_TN_MALICIOUS = 39023334
    total_per_packet_FP_MALICIOUS = 606721
    total_per_packet_FN_MALICIOUS = 11790518
    total_per_packet_TP_MALICIOUS = 48723573

    print("")
    print("#####################################################################################################################")
    print("Getting numbers for Random Forest Classifier")
    print("#####################################################################################################################")
    print_metrics(total_per_packet_TN_BENIGN, total_per_packet_FP_BENIGN, total_per_packet_FN_BENIGN, total_per_packet_TP_BENIGN, total_per_packet_TN_MALICIOUS, total_per_packet_FP_MALICIOUS, total_per_packet_FN_MALICIOUS, total_per_packet_TP_MALICIOUS)

    # This numbers are for Random Forest
    total_per_packet_TN_BENIGN = 47132100
    total_per_packet_FP_BENIGN = 13381991
    total_per_packet_FN_BENIGN = 1324687
    total_per_packet_TP_BENIGN = 38305368
    total_per_packet_TN_MALICIOUS = 38305368
    total_per_packet_FP_MALICIOUS = 1324687
    total_per_packet_FN_MALICIOUS = 13381991
    total_per_packet_TP_MALICIOUS = 47132100

    print("#####################################################################################################################")
    print("Getting numbers for DNN")
    print("#####################################################################################################################")
    print_metrics(total_per_packet_TN_BENIGN, total_per_packet_FP_BENIGN, total_per_packet_FN_BENIGN, total_per_packet_TP_BENIGN, total_per_packet_TN_MALICIOUS, total_per_packet_FP_MALICIOUS, total_per_packet_FN_MALICIOUS, total_per_packet_TP_MALICIOUS)


if __name__ == "__main__":
    main()