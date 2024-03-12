import math

from src.feature_extraction import config
from src.feature_extraction.F_opcodes import opcodes
from collections import Counter
from p_tqdm import p_map
from tqdm import tqdm
import os
import subprocess
import pickle
import pandas as pd
from functools import partial
from info_gain import info_gain
import numpy as np
from itertools import islice


def partialCounter(iSha1s):
    i = iSha1s[0]
    sha1s = iSha1s[1]
    topNGrams = Counter()
    for sha1 in sha1s:
        filepath = os.path.join(config.TEMP_DIRECTORY, sha1)
        current = pd.read_pickle(filepath)
        topNGrams.update(current)
    # Save to pickle
    filepath = os.path.join(config.TEMP_DIRECTORY, 'nGrams_partial_{}'.format(i))
    with open(filepath, 'wb') as wFile:
        pickle.dump(topNGrams, wFile)
    return


def partialTfIdf(frequences, experiment, topOpcodes, N, binary):
    sha1s = list(frequences.keys())
    consideredOpcodes = set(topOpcodes.keys())
    docFreq = pd.DataFrame(topOpcodes.values(), index=topOpcodes.keys(), columns=['idf'])
    idf = partial(opcodes.idf, N=N)
    docFreq['idf'] = docFreq['idf'].apply(idf)
    for sha1 in sha1s:
        opcodesCounter = frequences[sha1]

        # Take only those that are in the top opcodes N_grams
        consideredNgrams = Counter({k: v for k, v in opcodesCounter.items() if k in consideredOpcodes})
        consideredNgrams = pd.DataFrame(consideredNgrams.values(), index=consideredNgrams.keys(), columns=[sha1])
        consideredNgrams[sha1] = consideredNgrams[sha1].apply(opcodes.tf)
        docFreq = pd.concat([docFreq, consideredNgrams], axis=1)
    docFreq = docFreq.fillna(0.0)
    docFreq[sha1s] = docFreq[sha1s].multiply(docFreq['idf'], axis=0)
    docFreq = docFreq.drop('idf', axis=1)

    # Read labels and creating last row
    labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'labels.pickle'))
    if binary:
        docFreq.loc['benign', docFreq.columns] = labels.loc[docFreq.columns, 'benign']
    else:
        docFreq.loc['benign', docFreq.columns] = labels.loc[docFreq.columns, 'family']
    return docFreq


def computeInformationGain(opcodes, labels):
    retDf = pd.DataFrame(0.0, index=opcodes.index, columns=['IG'])
    for opcode, row in opcodes.iterrows():
        retDf.at[opcode, 'IG'] = info_gain.info_gain(labels, row)
    return retDf


def top_opCodes(plot, binary, experiment):
    sha1s = config.getList(experiment, validation=True, binary=binary)
    print("Extracting opcodes from all the samples in the validation set")
    # Clean temp folder
    subprocess.call('cd {} && rm -rf *'.format(config.TEMP_DIRECTORY), shell=True)
    ngrams_frequences = p_map(opcodes.extract, sha1s, num_cpus=config.CORES)
    ngrams_frequences = {k: v for d in ngrams_frequences for k, v in d.items()}

    # Checking problems with extraction
    problematicSha1s = {k: v for k, v in ngrams_frequences.items() if v['error']}
    config.updateLabelDataFrame(experiment, problematicSha1s)
    # ngrams_frequences = {k:v for k,v in ngrams_frequences.items() if not v['error']}
    ngrams_frequences = {k: v['ngrams'] for k, v in ngrams_frequences.items() if not v['error']}

    # #Add here could not disassemble
    # problematicSha1s = {k:{'error':'Disassembled is empty'} for k,v in ngrams_frequences.items() if not v['ngrams']}
    # config.updateLabelDataFrame(experiment,problematicSha1s)
    # ngrams_frequences = {k:v['ngrams'] for k,v in ngrams_frequences.items() if v['ngrams']}

    sha1s = ngrams_frequences.keys()
    samplesLen = len(sha1s)

    print("Computing document frequency")
    ngram_whole_dataset = Counter()
    for sha1Counter in tqdm(ngrams_frequences.values()):
        ngram_whole_dataset.update(Counter({k: 1 for k in sha1Counter.keys()}))

    print("Total number of unique opcodes nGrams is: {}".format(len(ngram_whole_dataset)))

    # Saving for plot
    if plot:
        print("Saving complete list for CCDF plot")
        filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'opcodes_count.pickle')
        with open(filepath, 'wb') as wFile:
            pickle.dump(ngram_whole_dataset, wFile)

    # Filtering the most and least common  (they carry no useful info)
    upperBound = int(len(ngram_whole_dataset) - len(ngram_whole_dataset) * .1 / 100)
    lowerBound = int(len(ngram_whole_dataset) * .1 / 100)
    topOpcodes = Counter({k: v for k, v in ngram_whole_dataset.items() if v > lowerBound and v < upperBound})

    # TF IDF
    print("Computing Tf-Idf")
    it = iter(ngrams_frequences)
    chunks = []
    perChunk = math.ceil(len(ngrams_frequences) / (4 * config.CORES))
    for i in range(0, len(ngrams_frequences), perChunk):
        chunks.append({k: ngrams_frequences[k] for k in islice(it, perChunk)})

    fun_partialTfIdf = partial(partialTfIdf, experiment=experiment, topOpcodes=topOpcodes, N=samplesLen, binary=binary)
    results = p_map(fun_partialTfIdf, chunks)
    tfIdf = pd.concat(results, axis=1)

    # Compute Information Gain
    print("Computing information gain")
    toReadd = tfIdf.loc['benign']
    tfIdf = tfIdf.drop('benign')
    chunks = np.array_split(tfIdf, config.CORES)
    fun_partialIG = partial(computeInformationGain, labels=toReadd)
    IG = p_map(fun_partialIG, chunks)
    IG = pd.concat(IG)

    # Render in matplotlib
    if plot:
        print("Saving opcodes IG for CCDF plot")
        filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'opcodes_ig.pickle')
        IG.to_pickle(filepath)

    # igThresh = input("Which IG value do you want to cut Opcodes?")
    # #Multiclass
    # igThresh = 0.4

    # #Binary
    # # igThresh = 0.025
    # IG  = IG[IG.IG>=float(igThresh)]
    IG = IG.sort_values(by='IG', ascending=False)
    IG = IG.head(2500)

    # Save opcodes and docFreq
    topOpcodes = Counter({k: v for k, v in topOpcodes.items() if k in IG.index})
    filepath = os.path.join(config.SELECT_DIRECTORY, experiment, 'opcodes.list')
    with open(filepath, 'w') as wFile:
        wFile.write("\n".join(topOpcodes))

    # Cleaning
    subprocess.call('cd {} && rm -rf *'.format(config.TEMP_DIRECTORY), shell=True)
    return


def postSelection_opCodes(binary, experiment):
    # loading top opcodes
    filepath = os.path.join(config.SELECT_DIRECTORY, experiment, 'opcodes.list')
    with open(filepath, 'r') as rFile:
        topOpcodes = rFile.read().splitlines()

    sha1s = config.getList(experiment, trainTest=True, binary=binary)

    # extracting opcodes from the training test set
    print("Extracting opcodes from the training/test set for computing the tf idf...")
    ngrams_frequences = p_map(opcodes.extract, sha1s, num_cpus=config.CORES)
    ngrams_frequences = {k: v for d in ngrams_frequences for k, v in d.items()}

    # Checking problems with extraction
    problematicSha1s = {k: v for k, v in ngrams_frequences.items() if v['error']}
    config.updateLabelDataFrame(experiment, problematicSha1s)
    # ngrams_frequences = {k:v for k,v in ngrams_frequences.items() if not v['error']}
    ngrams_frequences = {k: v['ngrams'] for k, v in ngrams_frequences.items() if not v['error']}

    # #Add here could not disassemble
    # problematicSha1s = {k:{'error':'Disassembled is empty'} for k,v in ngrams_frequences.items() if not v['ngrams']}
    # config.updateLabelDataFrame(experiment,problematicSha1s)
    # ngrams_frequences = {k:v['ngrams'] for k,v in ngrams_frequences.items() if v['ngrams']}

    sha1s = ngrams_frequences.keys()
    samplesLen = len(sha1s)

    print("Opcode extraction was successful for {} samples in training dataset. This is your N".format(samplesLen))

    print("Computing document frequency")
    ngram_whole_dataset = Counter()
    for sha1Counter in tqdm(ngrams_frequences.values()):
        ngram_whole_dataset.update(Counter({k: 1 for k in sha1Counter.keys()}))

    print("Only considering opcodes...")
    ngram_whole_dataset = Counter({k: v for k, v in ngram_whole_dataset.items() if k in topOpcodes})
    filepath = os.path.join(config.SELECT_DIRECTORY, experiment, 'trainTopOpcodesCounter.pickle')
    with open(filepath, 'wb') as wFile:
        pickle.dump(ngram_whole_dataset, wFile)
    return samplesLen
