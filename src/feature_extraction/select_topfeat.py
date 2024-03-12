#!/usr/bin/env python3
import config
from PRE_topFeatures import top_strings
from PRE_topFeatures import top_nGrams
from PRE_topFeatures import top_opCodes
from PRE_topFeatures import top_imports
from collections import Counter
from p_tqdm import p_map
from tqdm import tqdm
import matplotlib.pyplot as plt
import os
import pickle

def computeTopFeatures(plot,binary,experiment):
    # top_imports.top_imports(plot,binary,experiment)
    top_strings.top_strings(plot,binary,experiment)
    top_nGrams.top_nGrams(plot,binary,experiment)
    top_opCodes.top_opCodes(plot,binary,experiment)
    N = top_opCodes.postSelection_opCodes(binary,experiment)
    return N

