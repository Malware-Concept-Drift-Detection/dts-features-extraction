import os
import pickle
import random
import subprocess
import sys
from collections import Counter
from multiprocessing import Pool

import numpy as np
import pandas as pd
from info_gain import info_gain
from p_tqdm import p_map
from tqdm import tqdm

from src.feature_extraction import config
from src.feature_extraction.static.ngrams import NGramsExtractor
from src.feature_extraction.top_features.top_strings import create_chunks


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


def filter_out_very_unlikely(malware_dataset, experiment):
    sha1s = list(malware_dataset.training_dataset[['sha256', 'family']].to_numpy())
    subsample = 1000
    random.seed(42)
    sha1s_sample = random.sample(sha1s, subsample)

    print(f"Extracting n-grams from a randomly selected set of {subsample} samples from the training set")
    # Clean temp folder
    subprocess.call(f'cd {config.TEMP_DIRECTORY} && rm -rf *', shell=True)
    # #REMOVE
    # for x in sha1s:
    #     ngrams.extractAndSave(x)
    # #REMOVE
    ngrams_extractor = NGramsExtractor()
    # chunks = create_chunks(sha1s_sample, config.CORES)
    p_map(ngrams_extractor.extract_and_save, sha1s_sample, num_cpus=config.CORES)

    # Computing n-grams frequecy
    # (unique n-grams per binary so this means that if a nGram appears more than once
    # in the binary it is counted only once)
    print("Computing n-grams prevalence")
    sha1s_only = [s for s, _ in sha1s_sample]
    chunks = [sha1s_only[x:x + 100] for x in range(0, len(sha1s_only), 100)]
    chunks = list(zip(range(0, len(chunks)), chunks))
    p_map(partial_counter, chunks)

    print("Unifying counters")
    top_n_grams = Counter()
    for counter in tqdm(range(0, len(chunks))):
        filepath = os.path.join(config.TEMP_DIRECTORY, f'nGrams_partial_{counter}')
        partial = pd.read_pickle(filepath)
        top_n_grams.update(partial)

    print(f"Total number of unique n-grams is: {len(top_n_grams)}")

    # Saving for Matplotlib
    # if plot:
    #     print("Saving complete list for CCDF plot")
    #     filepath = os.path.join(config.PLOTS_DIRECTORY,experiment,'nGrams_count.pickle')
    #     with open(filepath, 'wb') as w_file:
    #         pickle.dump(top_n_grams,w_file)

    # Filtering the most and least common  (they carry no useful info)
    top_n_grams = Counter({k: v for k, v in top_n_grams.items() if 10 < v < 990})

    # Saving the list of nGrams and randomSha1s considered for the next step
    with open(f'./{config.TEMP_DIRECTORY}/top_n_grams.pickle', 'wb') as w_file:
        pickle.dump(top_n_grams, w_file)
    with open(f'./{config.TEMP_DIRECTORY}/sha1s', 'w') as w_file:
        w_file.write("\n".join(sha1s_only))

    # Rm temp files
    subprocess.call(f"cd {config.TEMP_DIRECTORY} && ls | grep partial | xargs rm", shell=True)
    return


def partial_df_IG(sha1s):
    with open(f'./{config.TEMP_DIRECTORY}/top_n_grams.pickle', 'rb') as rFile:
        top_n_grams = pickle.load(rFile)
    top_n_grams = top_n_grams.keys()
    df_IG = pd.DataFrame(True, index=top_n_grams, columns=[])
    for sha1 in sha1s:
        with open(f'./{config.TEMP_DIRECTORY}/{sha1}', 'rb') as rFile:
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


def compute_IG_for_likely_ones(malware_dataset, experiment):
    with open(f'./{config.TEMP_DIRECTORY}/sha1s', 'r') as r_file:
        sha1s = r_file.read().splitlines()
    print("Computing and merging relevant n-grams for sample files")
    chunks = [sha1s[i:i + 10] for i in range(0, len(sha1s), 10)]
    results = p_map(partial_df_IG, chunks, num_cpus=config.CORES)
    df_IG = pd.concat(results, axis=1)

    # Read labels and creating last row
    #labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'labels.pickle'))
    df = malware_dataset.df_malware_family_fsd
    df_IG.loc['benign', df_IG.columns] = df[df["sha256"].isin(list(df_IG.columns))]["family"]

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

    # igThresh = input("Which IG value do you want to cut Ngrams?")
    # # Multiclass
    # igThresh = 0.47
    # # Binary
    # # igThresh = 0.022
    # IG  = IG[IG.IG>=float(igThresh)]

    IG = IG.sort_values(by='IG', ascending=False)
    IG = IG.head(13000)
    IGs = ['ngram_' + x for x in IG.index]

    filepath = os.path.join(experiment, config.TOP_FEATURES_SUBDIR, 'ngrams.list')
    with open(filepath, 'w') as w_file:
        w_file.write("\n".join(IGs))

    # Cleaning
    subprocess.call(f'cd {config.TEMP_DIRECTORY} && rm -rf *', shell=True)


def top_n_grams(malware_dataset, experiment):
    filter_out_very_unlikely(malware_dataset, experiment)
    compute_IG_for_likely_ones(malware_dataset, experiment)
