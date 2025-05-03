import os
import pickle
from collections import Counter

from src.feature_extraction.config.config import config
from src.feature_extraction.static.static_feature_extractor import (
    StaticFeatureExtractor,
)


class NGramsExtractor(StaticFeatureExtractor):
    def extract_and_pad(self, args):
        filepath, top_n_grams = args
        with open(filepath, "rb") as f:
            all_bytes = f.read()
        return self.__extract_from_top(
            all_bytes=all_bytes, ngram_size=[4, 6], top_n_grams=top_n_grams
        )

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

    def __extract_from_top(self, all_bytes, ngram_size, top_n_grams):
        ngrams_in_malware = set()
        minsize = min(ngram_size)

        for i in range(len(all_bytes) - minsize):
            for s in ngram_size:
                ngram = all_bytes[i : i + s]
                if len(ngram) == s:
                    ngram = "ngram_" + str(ngram)
                    if ngram in top_n_grams:
                        ngrams_in_malware.add(ngram)

        # Put all ngrams to false and mark true only those intersected
        extracted_n_grams = dict.fromkeys(top_n_grams, False)
        for ngram in ngrams_in_malware:
            extracted_n_grams[ngram] = True

        return extracted_n_grams

    @staticmethod
    def __get_ngrams_from_bytes(all_bytes, ngram_size):
        ngrams = set()
        minsize = min(ngram_size)
        for i in range(len(all_bytes) - minsize):
            for s in ngram_size:
                ngram = all_bytes[i : i + s]
                if len(ngram) == s:
                    ngrams.add(str(ngram))
        return ngrams

    @staticmethod
    def __pad_ngrams(ngrams, top_n_grams):
        # Take only those that are in the top N_grams
        considered_ngrams = ngrams & top_n_grams

        # Put all ngrams to false and mark true only those intersected
        extracted_n_grams = dict.fromkeys(top_n_grams, False)
        for consideredNgram in considered_ngrams:
            extracted_n_grams[consideredNgram] = True
        return extracted_n_grams
