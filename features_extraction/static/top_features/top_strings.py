import os
from collections import Counter

from p_tqdm import p_map
from tqdm import tqdm

from features_extraction.config.config import config
from features_extraction.static.strings import StringsExtractor
from features_extraction.static.top_features.top_feature_extractor import (
    TopFeatureExtractor,
)
from features_extraction.utils import dump_data


class TopStrings(TopFeatureExtractor):
    def top(self, malware_dataset, experiment):
        sha1s = malware_dataset.training_dataset[["sha256", "family"]].to_numpy()
        samples_len = len(sha1s)
        print(
            f"Extracting strings from all the samples in the training set ({samples_len})"
        )
        strings_extractor = StringsExtractor()
        all_strings = p_map(
            strings_extractor.extract, sha1s, num_cpus=config.n_processes
        )

        # Computing strings frequency
        # (unique strings per binary so this means that if a string appears more than once
        # in the binary it is counted only once)
        print("Computing string prevalence")
        top_strings = Counter()
        for sample_strings in all_strings:
            top_strings.update(
                sample_strings
            )  # Set is important here for the frequency

        print("Total number of unique strings is: {}".format(len(top_strings.keys())))

        # Compute percentages
        print("Computing percentages and filtering")
        top_strings_percentages = Counter()
        for top_string_key, top_string_prevalence in tqdm(top_strings.items()):
            top_strings_percentages[top_string_key] = (
                top_string_prevalence / samples_len
            )

        # Fix thresholds:    we select 0.01 of the strings (discard 99.99% of them)
        #                   check how many times those strings appear (at least)
        #                   check in how many samples they appear

        threshold = int(len(top_strings) * 0.0001)
        top_strings_reduced = top_strings.most_common(threshold)
        top_strings_percentages_reduced = top_strings_percentages.most_common(threshold)
        seen_in_less_than = top_strings_reduced[-1][1]
        seen_in_less_than_percentage = top_strings_percentages_reduced[-1][1] * 100

        print(f"Selected strings: {len(top_strings_reduced)}")
        print(
            f"99.99% of the strings are seen in less than {seen_in_less_than} samples"
        )
        print(
            f"99.99% of the strings are seen in less than {seen_in_less_than_percentage}% of the samples"
        )

        # Save top_strings
        filepath = os.path.join(
            experiment, config.top_features_directory, "top_strings.pkl"
        )
        top_strings = ["str_" + s for s, _ in top_strings_reduced]
        dump_data(filepath, top_strings)
