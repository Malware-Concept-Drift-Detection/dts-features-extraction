import gc
import sys
from multiprocessing import Pool

from p_tqdm import p_map

from src.feature_extraction.static.static_feature_extractor import StaticFeatureExtractor
from src.feature_extraction import config
import os
import pickle
from collections import Counter
from nltk import ngrams
from guppy import hpy;

h = hpy()


class NGramsExtractor(StaticFeatureExtractor):

    def extract_and_pad(self, args):
        filepath, top_n_grams = args
        with open(filepath, 'rb') as f:
            all_bytes = f.read()
        ngrams = self.__get_ngrams_from_bytes(all_bytes, ngram_size=[4, 6])
        return self.__pad_ngrams(set(["ngram_" + ngram for ngram in set(ngrams)]), top_n_grams)

    def __get_ngrams_from_bytes(self, allbytes, ngram_size):
        j = 0
        ngrams = []
        for i in ngram_size:
            i_grams = []
            for k in range(len(allbytes) - i):
                ngram = allbytes[k:k + i]
                if len(ngram) == i:
                    j += 1
                    i_grams.append(str(ngram))
                # if j % 100_000 == 0:
                #     j = 0
                #     print("pruning")
                #     i_grams = list(set(i_grams))


            #print((sys.getsizeof(ngrams) + sys.getsizeof(allbytes)) / 10 ** 6)
            ngrams = ngrams + list(set(i_grams))
            del i_grams
            gc.collect()
        #print(h.heap())
        l = list(set(ngrams))


    # def __get_ngrams_from_bytes(self, allbytes, ngram_size):
    #     ngrams = []
    #     minsize = min(ngram_size)
    #     for i in range(len(allbytes) - minsize):
    #         for s in ngram_size:
    #             ngram = allbytes[i: i + s]
    #             if len(ngram) == s:
    #                 ngrams.append(str(ngram))
    #     return set(ngrams)

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
        for i, el in enumerate(sha1_family):
            print(i)
            sha1, family = el[0], el[1]
            filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
            with open(filepath, 'rb') as f:

                all_bytes = f.read()
                f.close()
            # print(os.path.getsize(filepath) / 10 ** 6)

            # Check the two
            self.__get_ngrams_from_bytes(all_bytes, ngram_size=[4, 6])
            # # jout = subprocess.check_output(['/worker/scratch/savino.dambra/pe-mal-class-code/classification
            # # /pipeline_updated/F_N_grams/rust_ngram', filepath], stderr=subprocess.STDOUT) jout = json.loads(
            # # subprocess.check_output(['/worker/scratch/savino.dambra/pe-mal-class-code/classification/pipeline_updated
            # # /F_N_grams/rust_ngram', filepath], stderr=subprocess.STDOUT)) ngrams2 = [] for a in [4,5,6]: ngrams2.extend([
            # # "".join(['{:x}'.format(x) for x in sublist]) for sublist in jout[str(a)]]) ngrams2 = set(ngrams2)
            # ngrams = Counter({k: 1 for k in ngrams})
            # save_path = os.path.join(config.TEMP_DIRECTORY, sha1)
            # with open(save_path, 'wb') as w_file:
            #     pickle.dump(ngrams, w_file)
            #     w_file.close()
            # gc.collect()
