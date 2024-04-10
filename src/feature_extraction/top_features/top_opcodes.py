import math
import os
import pickle
import subprocess
from collections import Counter
from functools import partial
from itertools import islice

import numpy as np
import pandas as pd
from info_gain import info_gain
from p_tqdm import p_map
from tqdm import tqdm

import src.feature_extraction.config as config
from src.feature_extraction.static.opcodes import OpCodesExtractor
from src.feature_extraction.top_features.top_feature_extractor import TopFeatureExtractor


class TopOpCodes(TopFeatureExtractor):

    def top(self, malware_dataset, experiment):
        sha1s = malware_dataset.training_dataset[['sha256', 'family']].to_numpy()
        print(f"Extracting opcodes from all {len(sha1s)} the samples in the training set")
        # Clean temp folder
        subprocess.call('cd {} && rm -rf *'.format(config.TEMP_DIRECTORY), shell=True)
        opcodes_extractor = OpCodesExtractor()
        n_grams_frequencies = p_map(opcodes_extractor.extract, sha1s, num_cpus=config.CORES)
        n_grams_frequencies = {k: v for d in n_grams_frequencies for k, v in d.items()}
        n_grams_frequencies = {k: v['ngrams'] for k, v in n_grams_frequencies.items() if not v['error']}
        sha1s = n_grams_frequencies.keys()
        samples_len = len(sha1s)

        print("Computing document frequency")
        ngram_whole_dataset = Counter()
        for sha1Counter in tqdm(n_grams_frequencies.values()):
            ngram_whole_dataset.update(Counter({k: 1 for k in sha1Counter.keys()}))

        print("Total number of unique opcodes n-grams is: {}".format(len(ngram_whole_dataset)))

        # Saving for plot
        # if plot:
        #     print("Saving complete list for CCDF plot")
        #     filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'opcodes_count.pickle')
        #     with open(filepath, 'wb') as w_file:
        #         pickle.dump(ngram_whole_dataset, w_file)

        # Filtering the most and least common  (they carry no useful info)
        upper_bound = int(len(ngram_whole_dataset) - len(ngram_whole_dataset) * .1 / 100)
        lower_bound = int(len(ngram_whole_dataset) * .1 / 100)
        top_opcodes = Counter({k: v for k, v in ngram_whole_dataset.items() if lower_bound < v < upper_bound})

        # TF IDF
        print("Computing Tf-Idf")
        it = iter(n_grams_frequencies)
        chunks = []
        per_chunk = math.ceil(len(n_grams_frequencies) / (4 * config.CORES))
        for i in range(0, len(n_grams_frequencies), per_chunk):
            chunks.append({k: n_grams_frequencies[k] for k in islice(it, per_chunk)})

        fun_partial_tf_idf = partial(self.__partial_tf_idf, malware_dataset=malware_dataset,
                                     experiment=experiment, top_opcodes=top_opcodes, N=samples_len)
        results = p_map(fun_partial_tf_idf, chunks)
        tf_idf = pd.concat(results, axis=1)

        # Compute Information Gain
        print("Computing information gain")
        to_readd = tf_idf.loc['benign']
        tf_idf = tf_idf.drop('benign')
        chunks = np.array_split(tf_idf, config.CORES)
        fun_partial_IG = partial(self.__compute_information_gain, labels=to_readd)
        ig = p_map(fun_partial_IG, chunks)
        ig = pd.concat(ig)

        # Render in matplotlib
        # if plot:
        #     print("Saving opcodes IG for CCDF plot")
        #     filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'opcodes_ig.pickle')
        #     IG.to_pickle(filepath)

        # igThresh = input("Which IG value do you want to cut Opcodes?")
        # #Multiclass
        # igThresh = 0.4

        # #Binary
        # # igThresh = 0.025
        # IG  = IG[IG.IG>=float(igThresh)]
        ig = ig.sort_values(by='IG', ascending=False)
        ig = ig.head(2500)

        # Save opcodes and docFreq
        top_opcodes = Counter({k: v for k, v in top_opcodes.items() if k in ig.index})
        filepath = os.path.join(experiment, config.TOP_FEATURES_SUBDIR, 'opcodes.list')
        with open(filepath, 'w') as w_file:
            w_file.write("\n".join(top_opcodes))

        # Cleaning
        subprocess.call(f'cd {config.TEMP_DIRECTORY} && rm -rf *', shell=True)

        self.__post_selection_op_codes(malware_dataset, experiment)

    # @staticmethod
    # def __partial_counter(i_sha1s):
    #     i = i_sha1s[0]
    #     sha1s = i_sha1s[1]
    #     top_n_grams = Counter()
    #     for sha1 in sha1s:
    #         filepath = os.path.join(config.TEMP_DIRECTORY, sha1)
    #         current = pd.read_pickle(filepath)
    #         top_n_grams.update(current)
    #     # Save to pickle
    #     filepath = os.path.join(config.TEMP_DIRECTORY, 'nGrams_partial_{}'.format(i))
    #     with open(filepath, 'wb') as wFile:
    #         pickle.dump(top_n_grams, wFile)
        return

    @staticmethod
    def __partial_tf_idf(frequences, malware_dataset, experiment, top_opcodes, N):
        sha1s = list(frequences.keys())
        considered_opcodes = set(top_opcodes.keys())
        doc_freq = pd.DataFrame(top_opcodes.values(), index=top_opcodes.keys(), columns=['idf'])
        opcodes_extractor = OpCodesExtractor()
        idf = partial(opcodes_extractor.idf, N=N)
        doc_freq['idf'] = doc_freq['idf'].apply(idf)
        for sha1 in sha1s:
            opcodes_counter = frequences[sha1]

            # Take only those that are in the top opcodes N_grams
            considered_ngrams = Counter({k: v for k, v in opcodes_counter.items() if k in considered_opcodes})
            considered_ngrams = pd.DataFrame(considered_ngrams.values(), index=considered_ngrams.keys(), columns=[sha1])
            considered_ngrams[sha1] = considered_ngrams[sha1].apply(opcodes_extractor.tf)
            doc_freq = pd.concat([doc_freq, considered_ngrams], axis=1)
        doc_freq = doc_freq.fillna(0.0)
        doc_freq[sha1s] = doc_freq[sha1s].multiply(doc_freq['idf'], axis=0)
        doc_freq = doc_freq.drop('idf', axis=1)

        # Read labels and creating last row
        df = malware_dataset.df_malware_family_fsd
        doc_freq.loc['benign', doc_freq.columns] = df[df["sha256"].isin(list(doc_freq.columns))]["family"]
        return doc_freq

    @staticmethod
    def __compute_information_gain(opcodes, labels):
        ret_df = pd.DataFrame(0.0, index=opcodes.index, columns=['IG'])
        for opcode, row in opcodes.iterrows():
            ret_df.at[opcode, 'IG'] = info_gain.info_gain(labels, row)
        return ret_df

    @staticmethod
    def __post_selection_op_codes(malware_dataset, experiment):

        # loading top opcodes
        filepath = os.path.join(experiment, config.TOP_FEATURES_SUBDIR, 'opcodes.list')
        with open(filepath, 'r') as r_file:
            top_opcodes = r_file.read().splitlines()

        # sha1s = config.get_list(experiment, train_test=True, binary=binary)
        sha1s = malware_dataset.df_malware_family_fsd[['sha256', 'family']].to_numpy()

        # extracting opcodes from the training test set
        print("Extracting opcodes from the training/test set for computing the tf idf...")
        opcodes_extractor = OpCodesExtractor()
        ngrams_frequences = p_map(opcodes_extractor.extract, sha1s, num_cpus=config.CORES)
        ngrams_frequences = {k: v for d in ngrams_frequences for k, v in d.items()}

        # Checking problems with extraction
        problematic_sha1s = {k: v for k, v in ngrams_frequences.items() if v['error']}
        # utils.update_label_data_frame(experiment, problematic_sha1s)
        # ngrams_frequences = {k:v for k,v in ngrams_frequences.items() if not v['error']}
        ngrams_frequences = {k: v['ngrams'] for k, v in ngrams_frequences.items() if not v['error']}

        # #Add here could not disassemble
        # problematic_sha1s = {k:{'error':'Disassembled is empty'} for k,v in ngrams_frequences.items() if not v['ngrams']}
        # config.updateLabelDataFrame(experiment,problematic_sha1s)
        # ngrams_frequences = {k:v['ngrams'] for k,v in ngrams_frequences.items() if v['ngrams']}

        sha1s = ngrams_frequences.keys()
        samples_len = len(sha1s)

        print(f"Opcode extraction was successful for {samples_len} samples in training dataset. This is your N")

        print("Computing document frequency")
        ngram_whole_dataset = Counter()
        for sha1Counter in tqdm(ngrams_frequences.values()):
            ngram_whole_dataset.update(Counter({k: 1 for k in sha1Counter.keys()}))

        print("Only considering opcodes...")
        ngram_whole_dataset = Counter({k: v for k, v in ngram_whole_dataset.items() if k in top_opcodes})
        filepath = os.path.join(experiment, config.TOP_FEATURES_SUBDIR, 'opcodes.pickle')
        with open(filepath, 'wb') as wFile:
            pickle.dump(ngram_whole_dataset, wFile)
        # return samples_len
