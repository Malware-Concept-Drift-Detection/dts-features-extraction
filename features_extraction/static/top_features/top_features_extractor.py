import logging
import os
from typing import List

from features_extraction.config.config import config
from features_extraction.static.top_features.top_feature_extractor import (
    TopFeatureExtractor,
)
from features_extraction.static.top_features.top_imports import TopImports
from features_extraction.static.top_features.top_ngrams import TopNGrams
from features_extraction.static.top_features.top_opcodes import TopOpCodes
from features_extraction.static.top_features.top_strings import TopStrings
from features_extraction.utils import dump_data, load_data
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


class TopFeaturesExtractor:
    def __init__(self, experiment_path):
        self.experiment_path = experiment_path
        self.base_top_path = os.path.join(
            experiment_path, config.top_features_directory
        )
        self.ig_byte_ngrams, self.ig_opcode_ngrams = (
            os.path.join(self.base_top_path, "ig_byte_ngrams.pkl"),
            os.path.join(self.base_top_path, "ig_opcode_ngrams.pkl"),
        )

        self.top_feature_extractors: List[TopFeatureExtractor] = [
            TopStrings(),
            TopImports(),
            TopNGrams(ig_filename=self.ig_byte_ngrams),
            TopOpCodes(ig_filename=self.ig_opcode_ngrams),
        ]

    def apply_ig_feature_selection(self):
        dfs = [
            load_data(ig_path)
            for ig_path in [self.ig_byte_ngrams, self.ig_opcode_ngrams]
        ]
        df_igs = pd.concat(dfs, axis=0)
        df_igs = df_igs.loc[~df_igs.index.duplicated(keep="first")]
        igs = df_igs["IG"]

        def ccdf(igs):
            sorted_data = igs.sort_values()
            n = len(igs)
            # CCDF values: fraction of points strictly greater than each value
            ccdf_vals = 1.0 - np.arange(1, n + 1) / n
            return sorted_data, ccdf_vals

        sorted_ig, ccdf_byte = ccdf(igs)
        ig_elbow = 0.45
        ccdf_elbow = ccdf_byte[sorted_ig >= ig_elbow][0]
        top_ngrams = sorted_ig[sorted_ig > ig_elbow].index

        ig_figure_path = os.path.join(self.base_top_path, "ccdf_ig_ngrams.png")

        plt.figure()
        plt.plot(sorted_ig, ccdf_byte)
        plt.axvline(ig_elbow, color="red", linestyle="--")
        plt.axhline(ccdf_elbow, color="red", linestyle="--")
        plt.xlabel("Information gain of bytes and opcode n-gram")
        plt.grid()
        plt.ylabel("CCDF")
        plt.savefig(ig_figure_path)

        top_byte_ngrams = top_ngrams[[isinstance(item, bytes) for item in top_ngrams]]
        top_opcode_ngrams = top_ngrams[
            [not isinstance(item, bytes) for item in top_ngrams]
        ]

        print(f"Top byte n-grams: {len(top_byte_ngrams)}")
        print(f"Top opcode n-grams: {len(top_opcode_ngrams)}")

        top_byte_ngrams_filename, top_opcode_ngrams_filename = (
            os.path.join(self.base_top_path, "top_byte_ngrams.pkl"),
            os.path.join(self.base_top_path, "ig_top_opcode_ngrams.pkl"),
        )

        # Dump top byte and opcode n-grams
        dump_data(top_byte_ngrams_filename, top_byte_ngrams)
        dump_data(top_opcode_ngrams_filename, top_opcode_ngrams)

    def extract_top_static_features(self, malware_dataset):
        # for top_feature_extractor in self.top_feature_extractors:
        #     top_feature_extractor.top(malware_dataset, self.experiment_path)
        self.apply_ig_feature_selection()
        for top_feature_extractor in self.top_feature_extractors:
            top_feature_extractor.post_feature_selection(
                malware_dataset, self.experiment_path
            )
