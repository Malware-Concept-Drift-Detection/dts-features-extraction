import os
import pickle
import random
import subprocess
from collections import Counter

import numpy as np
import pandas as pd
from info_gain import info_gain
from p_tqdm import p_map
from tqdm import tqdm

from features_extraction.static.top_features.top_feature_extractor import (
    TopFeatureExtractor,
)
from sklearn.feature_selection import mutual_info_classif
from features_extraction.config.config import config
from features_extraction.static.ngrams import NGramsExtractor
from features_extraction.utils import dump_data, load_data


class TopNGrams(TopFeatureExtractor):
    def __init__(self, ig_filename):
        super().__init__()
        self.ig_filename = ig_filename

    def top(self, malware_dataset, experiment):
        self.__filter_out_very_unlikely(malware_dataset, experiment)
        self.__compute_ig_for_likely_ones(malware_dataset, experiment)

    def __filter_out_very_unlikely(self, malware_dataset, experiment):
        ngrams_extractor = NGramsExtractor()

        sha_family = malware_dataset.training_dataset[["sha256", "family"]]
        sha_family_small = sha_family.to_numpy()
        sha1s = list(sha_family_small)

        n_subsample = 1000
        sha1s_sample = random.sample(sha1s, n_subsample)

        print(
            f"Extracting n-grams from a randomly selected set of {n_subsample} samples from the training set"
        )
        subprocess.call(
            f"mkdir -p {config.temp_results_dir} && cd {config.temp_results_dir} && rm -rf *",
            shell=True,
        )
        p_map(
            ngrams_extractor.extract_and_save, sha1s_sample, num_cpus=config.n_processes
        )

        # Computing n-grams frequecy
        # (unique n-grams per binary so this means that if a nGram appears more than once
        # in the binary it is counted only once)
        print("Computing n-grams prevalence")
        sha1s_only = [s for s, _ in sha1s_sample]
        chunk_len = 100
        chunks = [
            sha1s_only[x : x + chunk_len] for x in range(0, len(sha1s_only), chunk_len)
        ]
        chunks = list(zip(range(0, len(chunks)), chunks))
        p_map(self.__partial_counter, chunks)

        print("Unifying counters")
        top_n_grams = Counter()
        for counter in tqdm(range(len(chunks))):
            filepath = os.path.join(
                config.temp_results_dir, f"nGrams_partial_{counter}"
            )
            partial = pd.read_pickle(filepath)
            top_n_grams.update(partial)

        print(f"Total number of unique n-grams is: {len(top_n_grams)}")

        # Filtering the most and least common  (they carry no useful info)
        lb, ub = round(n_subsample / 100), round(n_subsample * 99 / 100)
        top_n_grams = Counter({k: v for k, v in top_n_grams.items() if lb < v < ub})

        items = list(top_n_grams.items())
        sample_size = min(5_000_000, len(items))
        random_sample = random.sample(items, sample_size)
        top_n_grams = Counter(dict(random_sample))

        # Saving the list of nGrams and randomSha1s considered for the next step
        top_ngrams_filename = os.path.join(
            config.temp_results_dir, "top_n_grams.pickle"
        )
        dump_data(top_ngrams_filename, top_n_grams)

        subsamples_sha_filename = os.path.join(config.temp_results_dir, "sha1s")
        with open(subsamples_sha_filename, "w") as w_file:
            w_file.write("\n".join(sha1s_only))

        # Rm temp (partial) files
        subprocess.call(
            f"cd {config.temp_results_dir} && ls | grep partial | xargs rm", shell=True
        )

    def __compute_ig_for_likely_ones(self, malware_dataset, experiment):
        with open(os.path.join(config.temp_results_dir, "sha1s"), "r") as r_file:
            sha1s = r_file.read().splitlines()

        print("Computing and merging relevant n-grams for sample files")
        chunks = [sha1s[i : i + 10] for i in range(0, len(sha1s), 10)]
        results = p_map(self.__partial_df_ig, chunks, num_cpus=config.n_processes)
        df_ig = pd.concat(results, axis=1)

        # Read labels and creating last row
        print("Copying training dataset")
        df_train = malware_dataset.training_dataset.copy()
        df_train.set_index("sha256", inplace=True)
        df_ig.loc["family", df_ig.columns] = df_train.loc[df_ig.columns]["family"]

        print("Chunks for information gain")
        to_add = df_ig.loc["family"]
        df_ig = df_ig.drop("family")
        chunks = np.array_split(df_ig, config.n_processes)
        for chunk in chunks:
            chunk.loc["family"] = to_add

        print("Computing information gain")
        results = p_map(
            self.__compute_information_gain, chunks, num_cpus=config.n_processes
        )
        ig = pd.concat(results)
        dump_data(self.ig_filename, ig)

        # igThresh = input("Which IG value do you want to cut Binary Ngrams?")
        # ig  = ig[ig["IG"] >= float(igThresh)]

        # ig = ig.head(13000)
        # IGs = ig.index

        # filepath = os.path.join(
        #     experiment, config.top_features_directory, "ngrams.list"
        # )
        # with open(filepath, "wb") as w_file:
        #     for ngram in IGs:
        #         w_file.write(ngram + b"\n")

        # Cleaning
        subprocess.call(f"cd {config.temp_results_dir} && rm -rf *", shell=True)

    @staticmethod
    def __partial_counter(i_sha1s):
        i, sha1s = i_sha1s
        top_n_grams = Counter()
        for sha1 in sha1s:
            filepath = os.path.join(config.temp_results_dir, sha1)
            current = pd.read_pickle(filepath)
            top_n_grams.update(current)
        # Save to pickle
        filepath = os.path.join(config.temp_results_dir, f"nGrams_partial_{i}")
        dump_data(filepath, top_n_grams)

    @staticmethod
    def __partial_df_ig(sha1s):
        top_n_grams = load_data(
            os.path.join(config.temp_results_dir, "top_n_grams.pickle")
        )
        top_n_grams = top_n_grams.keys()
        df_IG = pd.DataFrame(True, index=top_n_grams, columns=[])
        for sha1 in sha1s:
            n_grams = load_data(os.path.join(config.temp_results_dir, sha1))

            n_grams = set(n_grams.keys())
            # Take only those that are in the top N_grams
            considered_n_grams = n_grams & top_n_grams
            # Put all n_grams to false and mark true only those intersected
            extracted_n_grams = pd.Series(False, index=top_n_grams)
            for consideredNgram in considered_n_grams:
                extracted_n_grams[consideredNgram] = True
            df_IG[sha1] = extracted_n_grams
        return df_IG

    @staticmethod
    def __compute_information_gain(n_grams):
        labels = n_grams.loc["family"]
        n_grams = n_grams.drop("family")
        ret_dict = pd.DataFrame(0.0, index=n_grams.index, columns=["IG"])
        for ngram, row in n_grams.iterrows():
            ret_dict.at[ngram, "IG"] = info_gain.info_gain(labels, row)
        return ret_dict
