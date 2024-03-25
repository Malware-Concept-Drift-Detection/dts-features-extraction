import os
import pickle
from collections import Counter

import numpy as np

from src.feature_extraction.static.static_feature_extractor import StaticFeatureExtractor
from src.feature_extraction import config
import subprocess


class StringsExtractor(StaticFeatureExtractor):

    def extract(self, sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
        cmd = ['strings', filepath]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        output = proc.communicate()[0].decode("utf-8")
        strings = output.split('\n')
        strings = [string.strip() for string in strings]
        strings = [string for string in strings if len(string) > 3]

        unique_strings = list(Counter(strings).keys())
        # Saving the list of nGrams and randomSha1s considered for the next step
        # with open(f'./tmp/strings/sha1s/{sha1}.pickle', 'wb') as w_file:
        #     pickle.dump(unique_strings, w_file)
        #np.savetxt(f"./tmp/strings/sha1s/{sha1}.pickle", unique_strings)
        with open(f"./tmp/strings/sha1s/{sha1}.pickle", "w", encoding="utf-8") as file:
            # Write each string of the array to a separate line in the file
            for string in unique_strings:
                file.write(string + "\n")

    def extract_and_pad(self, args):
        filepath, top_strings = args
        cmd = ['strings', filepath]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        output = proc.communicate()[0].decode("utf-8")
        strings = output.split('\n')
        strings = [string.strip() for string in strings]
        strings = [string for string in strings if len(string) > 3]
        return self.__pad_strings(set(["str_" + s for s in strings]), top_strings)

    @staticmethod
    def __pad_strings(strings, top_strings):
        # Take only those that are in the top Strings
        considered_strings = strings & top_strings

        # Put all Strings to false and mark true only those intersected
        extracted_strings = dict.fromkeys(top_strings, False)
        for considered_string in considered_strings:
            extracted_strings[considered_string] = True
        return extracted_strings
