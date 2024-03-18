from src.dataset.setup_dataset import malware_dataset
from src.feature_extraction import config
from src.feature_extraction.static.ngrams import NGramsExtractor
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


def partial_counter(i_sha1s):
    i = i_sha1s[0]
    sha1s = i_sha1s[1]
    top_n_grams = Counter()
    for sha1 in sha1s:
        filepath = os.path.join(config.TEMP_DIRECTORY, sha1)
        current = pd.read_pickle(filepath)
        top_n_grams.update(current)
    # Save to pickle
    filepath = os.path.join(config.TEMP_DIRECTORY, 'nGrams_partial_{}'.format(i))
    with open(filepath, 'wb') as wFile:
        pickle.dump(top_n_grams, wFile)
    return


def filter_out_very_unlikely(binary, experiment):
    sha1s = malware_dataset.training_dataset[['sha256', 'family']].to_numpy() #config.get_list(experiment, validation=True, binary=binary, max_size=20)
    samples_len = len(sha1s)
    subsample = 1000
    sha1s = random.sample(sha1s, subsample)

    print("Extracting nGrams from a randomly selected set of {} samples from the training set".format(subsample))
    # Clean temp folder
    subprocess.call('cd {} && rm -rf *'.format(config.TEMP_DIRECTORY), shell=True)
    # #REMOVE
    # for x in sha1s:
    #     ngrams.extractAndSave(x)
    # #REMOVE
    ngrams_extractor = NGramsExtractor()
    p_map(ngrams_extractor.extract_and_save, sha1s, num_cpus=config.CORES)

    # Computing nGrams frequecy
    # (unique nGrams per binary so this means that if a nGram appears more than once
    # in the binary it is counted only once)
    print("Computing nGrams prevalence")
    sha1s_only = [s for s, _ in sha1s]
    chunks = [sha1s_only[x:x + 100] for x in range(0, len(sha1s_only), 100)]
    chunks = list(zip(range(0, len(chunks)), chunks))
    p_map(partial_counter, chunks)

    print("Unifying counters")
    top_n_grams = Counter()
    for counter in tqdm(range(0, len(chunks))):
        filepath = os.path.join(config.TEMP_DIRECTORY, 'nGrams_partial_{}'.format(counter))
        partial = pd.read_pickle(filepath)
        top_n_grams.update(partial)

    print("Total number of unique nGram is: {}".format(len(top_n_grams)))

    # Saving for Matplotlib
    # if plot:
    #     print("Saving complete list for CCDF plot")
    #     filepath = os.path.join(config.PLOTS_DIRECTORY,experiment,'nGrams_count.pickle')
    #     with open(filepath, 'wb') as w_file:
    #         pickle.dump(top_n_grams,w_file)

    # Filtering the most and least common  (they carry no useful info)
    top_n_grams = Counter({k: v for k, v in top_n_grams.items() if v > 10 and v < 990})

    # Saving the list of nGrams and randomSha1s considered for the next step
    with open('./{}/top_n_grams.pickle'.format(config.TEMP_DIRECTORY), 'wb') as w_file:
        pickle.dump(top_n_grams, w_file)
    with open('./{}/sha1s'.format(config.TEMP_DIRECTORY), 'w') as w_file:
        w_file.write("\n".join(sha1s_only))

    # Rm temp files
    subprocess.call("cd {} && ls | grep partial | xargs rm".format(config.TEMP_DIRECTORY), shell=True)
    return


def partial_df_IG(sha1s):
    with open('./{}/top_n_grams.pickle'.format(config.TEMP_DIRECTORY), 'rb') as rFile:
        top_n_grams = pickle.load(rFile)
    top_n_grams = set(top_n_grams.keys())
    df_IG = pd.DataFrame(True, index=top_n_grams, columns=[])
    for sha1 in sha1s:
        with open('./{}/{}'.format(config.TEMP_DIRECTORY, sha1), 'rb') as rFile:
            n_grams = pickle.load(rFile)

        n_grams = set(n_grams.keys())
        # Take only those that are in the top N_grams
        considered_n_grams = n_grams & top_n_grams

        # Put all n_grams to false and mark true only those intersected
        extracted_n_grams = pd.Series(False, index=top_n_grams)
        for consideredNgram in considered_n_grams:
            extracted_n_grams[consideredNgram] = True
        df_IG[sha1] = extracted_n_grams
    return df_IG


def compute_information_gain(n_grams):
    labels = n_grams.loc['benign']
    n_grams = n_grams.drop('benign')
    ret_dict = pd.DataFrame(0.0, index=n_grams.index, columns=['IG'])
    for ngram, row in n_grams.iterrows():
        ret_dict.at[ngram, 'IG'] = info_gain.info_gain(labels, row)
    return ret_dict


def compute_IG_for_likely_ones(binary, experiment):
    with open('./{}/sha1s'.format(config.TEMP_DIRECTORY), 'r') as r_file:
        sha1s = r_file.read().splitlines()
    print("Computing and merging relevant nGrams for sample files")
    chunks = [sha1s[i:i + 10] for i in range(0, len(sha1s), 10)]
    results = p_map(partial_df_IG, chunks, num_cpus=config.CORES)
    df_IG = pd.concat(results, axis=1)

    # Read labels and creating last row
    labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'labels.pickle'))
    if binary:
        df_IG.loc['benign', df_IG.columns] = labels.loc[df_IG.columns, 'benign']
    else:
        df_IG.loc['benign', df_IG.columns] = labels.loc[df_IG.columns, 'family']

    print("Chunks for information gain")
    keys = df_IG.keys()
    to_add = df_IG.loc['benign']
    df_IG = df_IG.drop('benign')
    chunks = np.array_split(df_IG, config.CORES)
    for chunk in chunks:
        chunk.loc['benign'] = to_add

    print("Computing information gain")
    results = p_map(compute_information_gain, chunks, num_cpus=config.CORES)
    IG = pd.concat(results)

    # Render in matplotlib
    # if plot:
    #     print("Saving nGrams IG for CCDF plot")
    #     filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'nGrams_ig.pickle')
    #     IG.to_pickle(filepath)

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
    with open(filepath, 'w') as w_file:
        w_file.write("\n".join(IGs))

    # Cleaning
    subprocess.call('cd {} && rm -rf *'.format(config.TEMP_DIRECTORY), shell=True)
    return


def top_n_grams(binary, experiment):
    filter_out_very_unlikely(binary, experiment)
    compute_IG_for_likely_ones(binary, experiment)
