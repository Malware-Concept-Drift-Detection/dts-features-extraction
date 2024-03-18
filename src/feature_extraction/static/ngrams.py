from src.feature_extraction.static.static_feature_extractor import StaticFeatureExtractor
from src.feature_extraction import config
import os
import pickle
from collections import Counter


class NGramsExtractor(StaticFeatureExtractor):

    def extract_and_pad(self, args):
        filepath, top_n_grams = args
        with open(filepath, 'rb') as f:
            all_bytes = f.read()
        ngrams = self.__get_ngrams_from_bytes(all_bytes, ngram_size=[4, 6])
        return self.__pad_ngrams(set(["ngram_" + ngram for ngram in set(ngrams)]), top_n_grams)

    @staticmethod
    def __get_ngrams_from_bytes(allbytes, ngram_size):
        ngrams = []
        minsize = min(ngram_size)
        for i in range(len(allbytes) - minsize):
            for s in ngram_size:
                ngram = allbytes[i:i + s]
                if len(ngram) == s:
                    ngrams.append(str(ngram))
        # We never need frequency for byte-nGrams
        ngrams = set(ngrams)
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

    def extract_and_save(self, sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
        with open(filepath, 'rb') as f:
            all_bytes = f.read()
        # Check the two
        ngrams = self.__get_ngrams_from_bytes(all_bytes, ngram_size=[4, 6])
        # jout = subprocess.check_output(['/worker/scratch/savino.dambra/pe-mal-class-code/classification
        # /pipeline_updated/F_N_grams/rust_ngram', filepath], stderr=subprocess.STDOUT) jout = json.loads(
        # subprocess.check_output(['/worker/scratch/savino.dambra/pe-mal-class-code/classification/pipeline_updated
        # /F_N_grams/rust_ngram', filepath], stderr=subprocess.STDOUT)) ngrams2 = [] for a in [4,5,6]: ngrams2.extend([
        # "".join(['{:x}'.format(x) for x in sublist]) for sublist in jout[str(a)]]) ngrams2 = set(ngrams2)
        ngrams = Counter({k: 1 for k in set(ngrams)})
        save_path = os.path.join(config.TEMP_DIRECTORY, sha1)
        with open(save_path, 'wb') as wFile:
            pickle.dump(ngrams, wFile)
        return
