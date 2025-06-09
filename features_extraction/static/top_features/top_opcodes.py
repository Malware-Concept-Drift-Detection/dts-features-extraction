import math
import os
import pickle
import subprocess
from collections import Counter
from functools import partial
from itertools import islice
from sklearn.decomposition import TruncatedSVD
from scipy.sparse import csr_matrix
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from info_gain import info_gain
from p_tqdm import p_map
from tqdm import tqdm

from features_extraction.config.config import config
from features_extraction.static.opcodes import OpCodesExtractor
from features_extraction.static.top_features.top_feature_extractor import (
    TopFeatureExtractor,
)


class TopOpCodes(TopFeatureExtractor):
    def top(self, malware_dataset, experiment):
        sha1s = malware_dataset.training_dataset[["sha256", "family"]].to_numpy()
        print(
            f"Extracting opcodes from all {len(sha1s)} the samples in the training set",
            flush=True,
        )
        # Clean temp folder
        subprocess.call("cd {} && rm -rf *".format(config.temp_results_dir), shell=True)
        opcodes_extractor = OpCodesExtractor()
        n_grams_frequencies = p_map(
            opcodes_extractor.extract, sha1s, num_cpus=config.n_processes
        )
        n_grams_frequencies = {k: v for d in n_grams_frequencies for k, v in d.items()}
        n_grams_frequencies = {
            k: v["ngrams"] for k, v in n_grams_frequencies.items() if not v["error"]
        }
        sha1s = n_grams_frequencies.keys()
        samples_len = len(sha1s)

        print("Computing document frequency")
        ngram_whole_dataset = Counter()
        for sha1Counter in tqdm(n_grams_frequencies.values()):
            ngram_whole_dataset.update(Counter({k: 1 for k in sha1Counter.keys()}))

        print(
            "Total number of unique opcodes n-grams is: {}".format(
                len(ngram_whole_dataset)
            )
        )

        # Filtering the most and least common  (they carry no useful info)
        upper_bound = int(
            len(ngram_whole_dataset) - len(ngram_whole_dataset) * 0.1 / 100
        )
        lower_bound = int(len(ngram_whole_dataset) * 0.1 / 100)
        top_opcodes = Counter(
            {
                k: v
                for k, v in ngram_whole_dataset.items()
                if lower_bound < v < upper_bound
            }
        )

        # TF IDF
        print("Computing Tf-Idf")
        it = iter(n_grams_frequencies)
        chunks = []
        per_chunk = math.ceil(len(n_grams_frequencies) / (4 * config.n_processes))
        for i in range(0, len(n_grams_frequencies), per_chunk):
            chunks.append({k: n_grams_frequencies[k] for k in islice(it, per_chunk)})

        fun_partial_tf_idf = partial(
            self.__partial_tf_idf,
            malware_dataset=malware_dataset,
            experiment=experiment,
            top_opcodes=top_opcodes,
            N=samples_len,
        )
        results = p_map(fun_partial_tf_idf, chunks)
        tf_idf = pd.concat(results, axis=1).T
        # tf_idf.to_csv("data/tf_idf.csv", index=True)
        # tf_idf = pd.read_csv("data/tf_idf.csv", index_col=0)

        column_names = tf_idf.columns
        print("Computing sparse matrix")
        X_sparse = csr_matrix(tf_idf.values)
        del tf_idf  # Free memory
        # Perform SVD to reduce dimensionality
        n_components = 100
        print("Computing SVD")
        svd = TruncatedSVD(n_components=n_components, random_state=config.random_seed)
        svd.fit(X_sparse)
        # Get the components and their absolute values
        components = np.abs(svd.components_)
        # Aggregate importance per feature (e.g., sum across components)
        feature_scores = components.sum(axis=0)  # shape: (n_features,)
        best_t = 0.8
        top_ngrams = column_names[feature_scores >= best_t]

        # Save top features
        cdf = [
            len(feature_scores[feature_scores <= i]) / len(feature_scores)
            for i in np.linspace(0, feature_scores.max(), 100)
        ]
        plt.figure(figsize=(10, 6))
        plt.plot(np.linspace(0, feature_scores.max(), 100), cdf)
        plt.title(
            "Cumulative Distribution Function of Opcode n-grams Feature Importance Scores"
        )
        plt.xlabel("Importance Score")
        plt.ylabel("Cumulative Count of Features")
        plt.grid()
        filepath = os.path.join(
            experiment,
            config.top_features_directory,
            "cdf_opcode_ngrams_importance.png",
        )
        plt.savefig(filepath)

        # Save opcodes and docFreq
        top_opcodes = Counter({k: v for k, v in top_opcodes.items() if k in top_ngrams})
        filepath = os.path.join(
            experiment, config.top_features_directory, "opcodes.list"
        )
        with open(filepath, "w") as w_file:
            w_file.write("\n".join(top_opcodes))

        # Cleaning
        subprocess.call(f"cd {config.temp_results_dir} && rm -rf *", shell=True)
        self.__post_selection_op_codes(malware_dataset, experiment)

    @staticmethod
    def __partial_tf_idf(frequences, malware_dataset, experiment, top_opcodes, N):
        sha1s = list(frequences.keys())
        considered_opcodes = set(top_opcodes.keys())
        doc_freq = pd.DataFrame(
            top_opcodes.values(), index=top_opcodes.keys(), columns=["idf"]
        )
        opcodes_extractor = OpCodesExtractor()
        idf = partial(opcodes_extractor.idf, N=N)
        doc_freq["idf"] = doc_freq["idf"].apply(idf)
        for sha1 in sha1s:
            opcodes_counter = frequences[sha1]

            # Take only those that are in the top opcodes N_grams
            considered_ngrams = Counter(
                {k: v for k, v in opcodes_counter.items() if k in considered_opcodes}
            )
            considered_ngrams = pd.DataFrame(
                considered_ngrams.values(),
                index=considered_ngrams.keys(),
                columns=[sha1],
            )
            considered_ngrams[sha1] = considered_ngrams[sha1].apply(
                opcodes_extractor.tf
            )
            doc_freq = pd.concat([doc_freq, considered_ngrams], axis=1)
        doc_freq = doc_freq.fillna(0.0)
        doc_freq[sha1s] = doc_freq[sha1s].multiply(doc_freq["idf"], axis=0)
        doc_freq = doc_freq.drop("idf", axis=1)

        # Read labels and creating last row
        # df = malware_dataset.df_malware_family_fsd
        # doc_freq.loc["benign", doc_freq.columns] = df[
        #     df["sha256"].isin(list(doc_freq.columns))
        # ]["family"]
        return doc_freq

    @staticmethod
    def __compute_information_gain(opcodes, labels):
        ret_df = pd.DataFrame(0.0, index=opcodes.index, columns=["IG"])
        for opcode, row in opcodes.iterrows():
            ret_df.at[opcode, "IG"] = info_gain.info_gain(labels, row)
        return ret_df

    @staticmethod
    def __post_selection_op_codes(malware_dataset, experiment):
        # loading top opcodes
        filepath = os.path.join(
            experiment, config.top_features_directory, "opcodes.list"
        )
        with open(filepath, "r") as r_file:
            top_opcodes = r_file.read().splitlines()

        sha1s = malware_dataset.df_malware_family_fsd[["sha256", "family"]].to_numpy()

        # extracting opcodes from the training test set
        print(
            "Extracting opcodes from the training/test set for computing the tf idf..."
        )
        opcodes_extractor = OpCodesExtractor()
        ngrams_frequences = p_map(
            opcodes_extractor.extract, sha1s, num_cpus=config.n_processes
        )
        ngrams_frequences = {k: v for d in ngrams_frequences for k, v in d.items()}
        ngrams_frequences = {
            k: v["ngrams"] for k, v in ngrams_frequences.items() if not v["error"]
        }

        sha1s = ngrams_frequences.keys()
        samples_len = len(sha1s)

        print(
            f"Opcode extraction was successful for {samples_len} samples in training dataset. This is your N"
        )

        print("Computing document frequency")
        ngram_whole_dataset = Counter()
        for sha1Counter in tqdm(ngrams_frequences.values()):
            ngram_whole_dataset.update(Counter({k: 1 for k in sha1Counter.keys()}))

        print("Only considering opcodes...")
        ngram_whole_dataset = Counter(
            {k: v for k, v in ngram_whole_dataset.items() if k in top_opcodes}
        )
        filepath = os.path.join(
            experiment, config.top_features_directory, "opcodes.pickle"
        )
        with open(filepath, "wb") as w_file:
            pickle.dump(ngram_whole_dataset, w_file)
