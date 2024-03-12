from src.feature_extraction import config
from src.feature_extraction.F_N_grams import ngrams
from collections import Counter
from p_tqdm import p_map
from tqdm import tqdm
import os
import subprocess
import pickle
import random
import pandas as pd
from info_gain import info_gain
import numpy as np


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


def filterOutVeryUnlikely(plot, binary, experiment):
    sha1s = config.getList(experiment, validation=True, binary=binary, maxSize=20)
    samplesLen = len(sha1s)
    subsample = 1000
    sha1s = random.sample(sha1s, subsample)

    print("Extracting nGrams from a randomly selected set of {} samples from the validation set".format(subsample))
    # Clean temp folder
    subprocess.call('cd {} && rm -rf *'.format(config.TEMP_DIRECTORY), shell=True)
    # #REMOVE
    # for x in sha1s:
    #     ngrams.extractAndSave(x)
    # #REMOVE
    p_map(ngrams.extractAndSave, sha1s, num_cpus=config.CORES)

    # Computing nGrams frequecy
    # (unique nGrams per binary so this means that if a nGram appears more than once
    # in the binary it is counted only once)
    print("Computing nGrams prevalence")
    sha1sOnly = [s for s, _ in sha1s]
    chunks = [sha1sOnly[x:x + 100] for x in range(0, len(sha1sOnly), 100)]
    chunks = list(zip(range(0, len(chunks)), chunks))
    p_map(partialCounter, chunks)

    print("Unifying counters")
    topNGrams = Counter()
    for counter in tqdm(range(0, len(chunks))):
        filepath = os.path.join(config.TEMP_DIRECTORY, 'nGrams_partial_{}'.format(counter))
        partial = pd.read_pickle(filepath)
        topNGrams.update(partial)

    print("Total number of unique nGram is: {}".format(len(topNGrams)))

    # Saving for Matplotlib
    # if plot:
    #     print("Saving complete list for CCDF plot")
    #     filepath = os.path.join(config.PLOTS_DIRECTORY,experiment,'nGrams_count.pickle')
    #     with open(filepath, 'wb') as wFile:
    #         pickle.dump(topNGrams,wFile)

    # Filtering the most and least common  (they carry no useful info)
    topNGrams = Counter({k: v for k, v in topNGrams.items() if v > 10 and v < 990})

    # Saving the list of nGrams and randomSha1s considered for the next step
    with open('./{}/topNGrams.pickle'.format(config.TEMP_DIRECTORY), 'wb') as wFile:
        pickle.dump(topNGrams, wFile)
    with open('./{}/sha1s'.format(config.TEMP_DIRECTORY), 'w') as wFile:
        wFile.write("\n".join(sha1sOnly))

    # Rm temp files
    subprocess.call("cd {} && ls | grep partial | xargs rm".format(config.TEMP_DIRECTORY), shell=True)
    return


def partialDfIG(sha1s):
    with open('./{}/topNGrams.pickle'.format(config.TEMP_DIRECTORY), 'rb') as rFile:
        topNGrams = pickle.load(rFile)
    topNGrams = set(topNGrams.keys())
    dfIG = pd.DataFrame(True, index=topNGrams, columns=[])
    for sha1 in sha1s:
        with open('./{}/{}'.format(config.TEMP_DIRECTORY, sha1), 'rb') as rFile:
            ngrams = pickle.load(rFile)

        ngrams = set(ngrams.keys())
        # Take only those that are in the top N_grams
        consideredNgrams = ngrams & topNGrams

        # Put all ngrams to false and mark true only those intersected
        extractedN_grams = pd.Series(False, index=topNGrams)
        for consideredNgram in consideredNgrams:
            extractedN_grams[consideredNgram] = True
        dfIG[sha1] = extractedN_grams
    return dfIG


def computeInformationGain(ngrams):
    labels = ngrams.loc['benign']
    ngrams = ngrams.drop('benign')
    retDict = pd.DataFrame(0.0, index=ngrams.index, columns=['IG'])
    for ngram, row in ngrams.iterrows():
        retDict.at[ngram, 'IG'] = info_gain.info_gain(labels, row)
    return retDict


def computeIGForLykelyOnes(plot, binary, experiment):
    with open('./{}/sha1s'.format(config.TEMP_DIRECTORY), 'r') as rFile:
        sha1s = rFile.read().splitlines()
    print("Computing and merging relevant nGrams for sample files")
    chunks = [sha1s[i:i + 10] for i in range(0, len(sha1s), 10)]
    results = p_map(partialDfIG, chunks, num_cpus=config.CORES)
    dfIG = pd.concat(results, axis=1)

    # Read labels and creating last row
    labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'labels.pickle'))
    if binary:
        dfIG.loc['benign', dfIG.columns] = labels.loc[dfIG.columns, 'benign']
    else:
        dfIG.loc['benign', dfIG.columns] = labels.loc[dfIG.columns, 'family']

    print("Chunks for information gain")
    keys = dfIG.keys()
    toAdd = dfIG.loc['benign']
    dfIG = dfIG.drop('benign')
    chunks = np.array_split(dfIG, config.CORES)
    for chunk in chunks:
        chunk.loc['benign'] = toAdd

    print("Computing information gain")
    results = p_map(computeInformationGain, chunks, num_cpus=config.CORES)
    IG = pd.concat(results)

    # Render in matplotlib
    if plot:
        print("Saving nGrams IG for CCDF plot")
        filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'nGrams_ig.pickle')
        IG.to_pickle(filepath)

    # igThresh = input("Which IG value do you want to cut Ngrams?")
    # # Multiclass
    # igThresh = 0.47
    # # Binary
    # # igThresh = 0.022
    # IG  = IG[IG.IG>=float(igThresh)]

    IG = IG.sort_values(by='IG', ascending=False)
    IG = IG.head(13000)
    IGs = ['ngram_' + x for x in IG.index]

    filepath = os.path.join(config.SELECT_DIRECTORY, experiment, 'nGrams.list')
    with open(filepath, 'w') as wFile:
        wFile.write("\n".join(IGs))

    # Cleaning
    subprocess.call('cd {} && rm -rf *'.format(config.TEMP_DIRECTORY), shell=True)
    return


def top_nGrams(plot, binary, experiment):
    filterOutVeryUnlikely(plot, binary, experiment)
    computeIGForLykelyOnes(plot, binary, experiment)
