#!/usr/bin/env python3
import config
import os
from collections import Counter
import pickle
import pandas as pd
import json
import subprocess

def get_ngrams_from_bytes(allbytes, ngram_size): 
    ngrams = []
    minsize = min(ngram_size)
    for i in range(len(allbytes) - minsize):
        for s in ngram_size:
            ngram = allbytes[i:i+s]
            if len(ngram) == s:
                ngrams.append(str(ngram))
    #We never need frequency for byte-nGrams
    ngrams = set(ngrams)
    return ngrams

def padNgrams(ngrams,topN_grams):
    #Take only those that are in the top N_grams
    consideredNgrams = ngrams & topN_grams

    #Put all ngrams to false and mark true only those intersected
    extractedN_grams = dict.fromkeys(topN_grams,False)
    for consideredNgram in consideredNgrams:
        extractedN_grams[consideredNgram] = True
    return extractedN_grams

def extractAndSave(sha1_family):
    sha1,family = sha1_family
    if family:
        filepath = os.path.join(config.MALWARE_DIRECTORY,family,sha1)
    else:
        filepath = os.path.join(config.GOODWARE_DIRECTORY,sha1)
    with open(filepath, 'rb') as f:
        allbytes = f.read()
    #Check the two
    ngrams = get_ngrams_from_bytes(allbytes, ngram_size=[4, 6])
    # jout = subprocess.check_output(['/worker/scratch/savino.dambra/pe-mal-class-code/classification/pipeline_updated/F_N_grams/rust_ngram', filepath], stderr=subprocess.STDOUT)
    # jout = json.loads(subprocess.check_output(['/worker/scratch/savino.dambra/pe-mal-class-code/classification/pipeline_updated/F_N_grams/rust_ngram', filepath], stderr=subprocess.STDOUT))
    # ngrams2 = []
    # for a in [4,5,6]:
        # ngrams2.extend(["".join(['{:x}'.format(x) for x in sublist]) for sublist in jout[str(a)]])
    # ngrams2 = set(ngrams2)
    ngrams = Counter({k:1 for k in set(ngrams)})
    savePath = os.path.join(config.TEMP_DIRECTORY,sha1)
    with open(savePath,'wb') as wFile:
        pickle.dump(ngrams,wFile)
    return 

def extractAndPad(filepath,topN_grams):
    with open(filepath, 'rb') as f:
        allbytes = f.read()
    ngrams = get_ngrams_from_bytes(allbytes, ngram_size=[4, 6])
    return padNgrams(set(["ngram_"+ngram for ngram in set(ngrams)]),topN_grams)
