import os
import pickle
from collections import Counter

from features_extraction.config.config import config
from features_extraction.static.static_feature_extractor import (
    StaticFeatureExtractor,
)


class NGramsExtractor(StaticFeatureExtractor):
    def extract_and_pad(self, args):
        filepath, top_n_grams = args
        with open(filepath, "rb") as f:
            all_bytes = f.read()
        ngrams_in_malware = self.__get_ngrams_from_bytes(all_bytes, ngram_size=[4, 6])
        return self.__pad_ngrams(ngrams_in_malware, top_n_grams)

    def shas_list_max_size(self, sha_family, mb_size):
        def get_file_size_mb(row):
            filepath = os.path.join(
                config.malware_directory_path, row["family"], row["sha256"]
            )
            size_bytes = os.path.getsize(filepath)
            return size_bytes / (1024**2)  # Convert to MB

        sha_family["size_mb"] = sha_family.apply(get_file_size_mb, axis=1)
        sha_family = sha_family[sha_family["size_mb"] <= mb_size]
        sha_family = sha_family.drop(columns=["size_mb"])
        return sha_family

    def extract_and_save(self, sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.malware_directory_path, family, sha1)
        with open(filepath, "rb") as f:
            all_bytes = f.read()
        ngrams = self.__get_ngrams_from_bytes(all_bytes, ngram_size=[4, 6])
        ngrams = Counter({k: 1 for k in ngrams})
        save_path = os.path.join(config.temp_results_dir, sha1)
        with open(save_path, "wb") as w_file:
            pickle.dump(ngrams, w_file)

    @staticmethod
    def __get_ngrams_from_bytes(all_bytes, ngram_size):
        minsize = min(ngram_size)
        return {
            all_bytes[i : i + s]
            for i in range(len(all_bytes) - minsize)
            for s in ngram_size
            if len(all_bytes[i : i + s]) == s
        }

    @staticmethod
    def __pad_ngrams(ngrams, top_n_grams):
        # Take only those that are in the top N_grams
        considered_ngrams = ngrams & top_n_grams

        # Put all ngrams to false and mark true only those intersected
        extracted_n_grams = dict.fromkeys(top_n_grams, False)
        for consideredNgram in considered_ngrams:
            extracted_n_grams[consideredNgram] = True
        return extracted_n_grams
