#!/bin/bash

# for BIN_WIDTH in 1 16 32 64 128 256
# do
#     for IPT_BIN_WIDTH in 0 1 10 60 300 900
#     do
#         python runExperiment.py $BIN_WIDTH $IPT_BIN_WIDTH
#     done
# done

for BIN_WIDTH in 32; do
    for IPT_BIN_WIDTH in 64; do
        python $1 --parentdir $2 --QL_PL $BIN_WIDTH --QL_IPT $IPT_BIN_WIDTH
    done
done