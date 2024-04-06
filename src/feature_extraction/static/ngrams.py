import os
import pickle
from collections import Counter

from src.feature_extraction import config
from src.feature_extraction.static.static_feature_extractor import StaticFeatureExtractor


class NGramsExtractor(StaticFeatureExtractor):

    def extract_and_pad(self, args):
        filepath, top_n_grams = args
        with open(filepath, 'rb') as f:
            all_bytes = f.read()
        #ngrams = self.__get_ngrams_from_bytes(all_bytes, ngram_size=[4, 6])
        #return self.__extract_from_top(set(["ngram_" + ngram for ngram in set(ngrams)]), ngram_size=[4, 6], top_n_grams=top_n_grams)
        return self.__extract_from_top(all_bytes=all_bytes, ngram_size=[4, 6], top_n_grams=top_n_grams)



    def __extract_from_top(self, all_bytes, ngram_size, top_n_grams):
        ngrams_in_malware = set()
        minsize = min(ngram_size)
        for i in range(len(all_bytes) - minsize):
            for s in ngram_size:
                ngram = all_bytes[i:i + s]
                if len(ngram) == s:
                    if ngram in top_n_grams:
                        ngrams_in_malware.update(ngram)

        # Put all ngrams to false and mark true only those intersected
        extracted_n_grams = dict.fromkeys(top_n_grams, False)
        for ngram in ngrams_in_malware:
            extracted_n_grams[ngram] = True
        return extracted_n_grams


    def extract_and_save(self, sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
        with open(filepath, 'rb') as f:
            all_bytes = f.read()
        ngrams = self.__get_ngrams_from_bytes(all_bytes, ngram_size=[4, 6])
        ngrams = Counter({k: 1 for k in ngrams})
        save_path = os.path.join(config.TEMP_DIRECTORY, sha1)
        with open(save_path, 'wb') as w_file:
            pickle.dump(ngrams, w_file)

    @staticmethod
    def __get_ngrams_from_bytes(all_bytes, ngram_size):
        ngrams = set()
        minsize = min(ngram_size)
        for i in range(len(all_bytes) - minsize):
            i_ngrams = set()
            for s in ngram_size:
                ngram = all_bytes[i:i + s]
                if len(ngram) == s:
                    i_ngrams.update(str(ngram))
            ngrams.update(i_ngrams)
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
