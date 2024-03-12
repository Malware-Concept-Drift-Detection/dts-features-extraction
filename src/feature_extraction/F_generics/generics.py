import math
from collections import Counter


# It is impossible to get a failure with this function so no dictionary needed with error
def extract(filepath):
    with open(filepath, 'rb') as f:
        byteArr = f.read()
        fileSize = len(byteArr)

    # calculate the frequency of each byte value in the file
    freqs = Counter()
    for byte in byteArr:
        freqs[byte] += 1
    freqList = [float(freqs[byte]) / float(fileSize) for byte in range(256)]

    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        if freq > 0:
            ent = ent + freq * math.log(freq, 2)
    ent = -ent

    generics = {'generic_fileSize': fileSize, 'generic_fileEntropy': ent}
    return generics
