import os

import numpy as np

from src.feature_extraction.static.static_feature_extractor import StaticFeatureExtractor
from src.feature_extraction import config
import subprocess


class StringsExtractor(StaticFeatureExtractor):

    def extract(self, sha1_family):
        all_strings = []
        sha1, family = sha1_family
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
        cmd = ['strings', filepath]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        output = proc.communicate()[0].decode("utf-8")
        strings = output.split('\n')
        for string in strings:
            s = string.strip()
            if len(s) > 3:
                all_strings.append(s)
        return list(set(all_strings))

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
