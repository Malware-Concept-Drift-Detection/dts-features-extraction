import os
import pickle
import random
import subprocess
from collections import Counter

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from info_gain import info_gain
from p_tqdm import p_map
from tqdm import tqdm
from sklearn.decomposition import TruncatedSVD
from scipy.sparse import csr_matrix

from features_extraction.static.top_features.top_feature_extractor import (
    TopFeatureExtractor,
)
from sklearn.feature_selection import mutual_info_classif
from features_extraction.config.config import config
from features_extraction.static.ngrams import NGramsExtractor


class TopNGrams(TopFeatureExtractor):
    def top(self, malware_dataset, experiment):
        self.__filter_out_very_unlikely(malware_dataset, experiment)
        self.__compute_ig_for_likely_ones(malware_dataset, experiment)

    def __filter_out_very_unlikely(self, malware_dataset, experiment):
        sha1s = list(malware_dataset.training_dataset[["sha256", "family"]].to_numpy())
        n_subsample = 1000
        sha1s_sample = random.sample(sha1s, n_subsample)

        print(
            f"Extracting n-grams from a randomly selected set of {n_subsample} samples from the training set"
        )
        subprocess.call(
            f"mkdir -p {config.temp_results_dir} && cd {config.temp_results_dir} && rm -rf *",
            shell=True,
        )
        ngrams_extractor = NGramsExtractor()
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
        for counter in tqdm(range(0, len(chunks))):
            filepath = os.path.join(
                config.temp_results_dir, f"nGrams_partial_{counter}"
            )
            partial = pd.read_pickle(filepath)
            top_n_grams.update(partial)

        print(f"Total number of unique n-grams is: {len(top_n_grams)}")

        # Filtering the most and least common  (they carry no useful info)
        # Equal to VarianceThreshold(0.01)
        lb, ub = round(n_subsample / 100), round(n_subsample * 99 / 100)
        top_n_grams = Counter({k: v for k, v in top_n_grams.items() if lb < v < ub})

        # Saving the list of nGrams and randomSha1s considered for the next step
        top_ngrams_filename = os.path.join(
            config.temp_results_dir, "top_n_grams.pickle"
        )
        with open(top_ngrams_filename, "wb") as w_file:
            pickle.dump(top_n_grams, w_file)

        subsamples_sha_filename = os.path.join(config.temp_results_dir, "sha1s")
        with open(subsamples_sha_filename, "w") as w_file:
            w_file.write("\n".join(sha1s_only))

        # Rm temp (partial) files
        subprocess.call(
            f"cd {config.temp_results_dir} && ls | grep partial | xargs rm", shell=True
        )

    def __compute_ig_for_likely_ones(self, malware_dataset, experiment):
        with open(f"./{config.temp_results_dir}/sha1s", "r") as r_file:
            sha1s = r_file.read().splitlines()

        print("Computing and merging relevant n-grams for sample files")
        chunks = [sha1s[i : i + 10] for i in range(0, len(sha1s), 10)]
        results = p_map(self.__partial_df_ig, chunks, num_cpus=config.n_processes)
        df_ig = pd.concat(results, axis=1).T
        print("Opening file", flush=True)
        # df_ig = pd.read_csv("data/df_ig.csv", index_col=0, engine="pyarrow").T

        # df_ig.to_csv("./data/df_ig.csv", index=True)

        column_names = df_ig.columns
        print("Computing sparse matrix")
        X_sparse = csr_matrix(df_ig.values)
        del df_ig  # Free memory
        # Perform SVD to reduce dimensionality
        n_components = 100
        print("Computing SVD")
        svd = TruncatedSVD(n_components=n_components, random_state=config.random_seed)
        svd.fit(X_sparse)
        # Get the components and their absolute values
        components = np.abs(svd.components_)
        # Aggregate importance per feature (e.g., sum across components)
        feature_scores = components.sum(axis=0)  # shape: (n_features,)
        best_t = 0.085
        top_ngrams = column_names[feature_scores >= best_t]
        assert len(top_ngrams) <= 20_000
        # Save top features
        cdf = [
            len(feature_scores[feature_scores <= i]) / len(feature_scores)
            for i in np.linspace(0, feature_scores.max(), 100)
        ]
        plt.figure(figsize=(10, 6))
        plt.plot(np.linspace(0, feature_scores.max(), 100), cdf)
        plt.title(
            "Cumulative Distribution Function of Binary n-grams Feature Importance Scores"
        )
        plt.xlabel("Importance Score")
        plt.ylabel("Cumulative Count of Features")
        plt.grid()
        filepath = os.path.join(
            experiment, config.top_features_directory, "cdf_bin_ngrams_importance.png"
        )
        plt.savefig(filepath)

        print("Saving top n-grams")
        filepath = os.path.join(
            experiment, config.top_features_directory, "ngrams.list"
        )
        with open(filepath, "wb") as w_file:
            for ngram in top_ngrams:
                w_file.write(ngram.encode("utf-8") + b"\n")

        # Cleaning
        subprocess.call(f"cd {config.temp_results_dir} && rm -rf *", shell=True)

    @staticmethod
    def __partial_counter(i_sha1s):
        i = i_sha1s[0]
        sha1s = i_sha1s[1]
        top_n_grams = Counter()
        for sha1 in sha1s:
            filepath = os.path.join(config.temp_results_dir, sha1)
            current = pd.read_pickle(filepath)
            top_n_grams.update(current)
        # Save to pickle
        filepath = os.path.join(config.temp_results_dir, "nGrams_partial_{}".format(i))
        with open(filepath, "wb") as wFile:
            pickle.dump(top_n_grams, wFile)

    @staticmethod
    def __partial_df_ig(sha1s):
        with open(f"./{config.temp_results_dir}/top_n_grams.pickle", "rb") as rFile:
            top_n_grams = pickle.load(rFile)
        top_n_grams = top_n_grams.keys()
        df_IG = pd.DataFrame(True, index=top_n_grams, columns=[])
        for sha1 in sha1s:
            with open(f"./{config.temp_results_dir}/{sha1}", "rb") as rFile:
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

    @staticmethod
    def __compute_information_gain(n_grams):
        labels = n_grams.loc["family"]
        n_grams = n_grams.drop("family")
        ret_dict = pd.DataFrame(0.0, index=n_grams.index, columns=["IG"])
        for ngram, row in n_grams.iterrows():
            ret_dict.at[ngram, "IG"] = info_gain.info_gain(labels, row)
        return ret_dict
