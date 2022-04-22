# import random
from keras.metrics import CategoricalAccuracy
from sklearn import metrics as sklmetrics
from helpers import makeLUTsFromModel
from keras.models import Sequential
from tqdm.keras import TqdmCallback
import tensorflow_addons as tfa
from keras.layers import Dense
from tensorflow import keras
import tensorflow as tf
import numpy as np
import csv
import os


class DNN:

    def __init__(self, model_name, arch, input_dim, output_dim, metrics):
        self.model_name = model_name + "_DNN"
        self.model = None
        self.arch = arch
        self.input_dim = input_dim
        self.output_dim = output_dim
        self.metrics = metrics

    def getModelLayers(self):
        arch, layers = [], []
        for layer in self.model.layers:
            if ((len(layer.get_weights()[1])) == 0):
                print(self.model)
            arch.append(len(layer.get_weights()[1]))
            layers.append(layer.get_weights())
        print("Architecture of the Model = {0}".format(arch))
        return layers

    def print_model_layers(self):
        for i, layer in enumerate(self.getModelLayers()):
            print("Layer-{0}".format(i))
            print(layer)

    def WriteModel(self, luts_dir):
        layers = self.getModelLayers()
        makeLUTsFromModel(layers, luts_dir)

    def build(self, no_compile=False):
        model = Sequential()
        # print(self.arch)
        # print(self.input_dim)
        # print(self.output_dim)
        model.add(keras.Input(shape=(self.input_dim,))) 
        for layer_idx, num_hidden_units in enumerate(self.arch):
            # if num_hidden_units == 0:
            #    continue

            # if layer_idx == 0:
            #     model.add(Dense(num_hidden_units, input_dim=self.input_dim, activation='relu'))
            # else:
            #     model.add(Dense(num_hidden_units, activation='relu'))
            model.add(Dense(num_hidden_units, activation='relu'))

        model.add(Dense(self.output_dim, activation='softmax'))
        if not no_compile:
            model.compile(loss='categorical_crossentropy', optimizer='adam',
                        #   metrics=["accuracy"])
                        # metrics=[CategoricalAccuracy()])
                        metrics=[tfa.metrics.F1Score(num_classes=2)])
        self.model = model

    def load_custom_model_from_CSVs(self, csv_dir_path):
        
        for i in range(len(self.arch)+1):
            
            # read weights for this layer
            this_layer_weights_file = os.path.join(csv_dir_path, "L{0}_NEURON_W_LUT.csv".format(i))
            with open(this_layer_weights_file) as this_file:
                this_layer_weights = []
                all_rows = csv.reader(this_file)
                for row in all_rows:
                    this_layer_weights.append(list(map(float, row)))

            # read weights for this layer
            this_layer_bias_file = os.path.join(csv_dir_path, "L{0}_NEURON_B_LUT.csv".format(i))
            with open(this_layer_bias_file) as this_file:
                this_layer_bias = []
                all_rows = csv.reader(this_file)
                for row in all_rows:
                    this_layer_bias.append(list(map(float, row)))
            
            # convert the weights and bias lists to numpy arrays
            this_layer_weights = np.transpose(np.array(this_layer_weights))
            this_layer_bias = np.transpose(np.reshape(np.array(this_layer_bias), (-1,)))
            print("Layer-{0} Weights = {1}".format(i, this_layer_weights.shape))
            print("Layer-{0} Bias = {1}".format(i, this_layer_bias.shape))
            # assign weights and bias to this layer
            self.model.layers[i].set_weights([this_layer_weights, this_layer_bias])
            
    def train(self, trainX, trainY, epochs, batch_size):
        # print(np.argmax(trainY, 1))
        tnx = np.reshape(trainX, (len(trainX), len(trainX[0])))
        tny = np.reshape(trainY, (len(trainY), len(trainY[0])))
        self.model.fit(tnx, tny, epochs=epochs, batch_size=batch_size, validation_split=0.1, verbose=0, callbacks=[TqdmCallback(verbose=1)])
        # ty = self.model.predict(trainX)
        # y = self.model.predict(np.reshape(trainX, np.shape(trainX)))
        # print(np.argmax(y, 1))

    def evaluate(self, testX, testY, invert_prediction_labels=False):
        # self.model.summary()
        print("____________________________________________")
        # self.print_model_layers()
        y = self.model.predict(np.reshape(testX, np.shape(testX)))
        
        # print(y)
        predicted_labels = np.argmax(y, 1)
        # # small fix for homunculus trained model
        # if invert_prediction_labels:
        #     predicted_labels = 1 - predicted_labels
        # result = filter(lambda x: not(x==0), predicted_labels)
        true_labels = np.argmax(testY, 1)
        # m = Metric.get("f1").getValue(true_labels, predicted_labels)
        
        f1 = 100*sklmetrics.f1_score(true_labels, predicted_labels, average="weighted", labels=np.unique(predicted_labels))
        confusion_matrix = tf.math.confusion_matrix(true_labels, predicted_labels, num_classes=2)

        print("++++++++++++++++++++++++++++++++++++++++++++++")
        unique_labels = np.unique(list(predicted_labels))
        print("Unique labels in test set = ", unique_labels)
        # print(list(true_labels))
        print("Test Set F1 Score = {0:.2f}".format(f1))
        print(confusion_matrix)

        # # fix the confusion matrix if necessary
        # if len(unique_labels == 1):
        #     if unique_labels[0] == 0:
        #         confusion_matrix = np.array([[confusion_matrix[0,0], 0], [0, 0]])
        #     elif unique_labels[0] == 1:
        #         confusion_matrix = np.array([[0, 0], [0, confusion_matrix[0,0]]])
        # print("Fixed Confusion Matrix = {0}".format(confusion_matrix))
        # print(confusion_matrix.shape)
        print("____________________________________________")
        return confusion_matrix