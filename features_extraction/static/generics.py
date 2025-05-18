import math
from collections import Counter

from features_extraction.static.static_feature_extractor import (
    StaticFeatureExtractor,
)


class GenericExtractor(StaticFeatureExtractor):
    # It is impossible to get a failure with this function so no dictionary needed with error
    def extract(self, filepath):
        with open(filepath, "rb") as f:
            byte_arr = f.read()
            file_size = len(byte_arr)

        # calculate the frequency of each byte value in the file
        freqs = Counter()
        for byte in byte_arr:
            freqs[byte] += 1
        freq_list = [float(freqs[byte]) / float(file_size) for byte in range(256)]

        # Shannon entropy
        ent = 0.0
        for freq in freq_list:
            if freq > 0:
                ent = ent + freq * math.log(freq, 2)
        ent = -ent

        generics = {"generic_fileSize": file_size, "generic_fileEntropy": ent}
        return generics
