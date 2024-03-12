#!/usr/bin/env python3
import config
from F_imports import imports
from collections import Counter
from p_tqdm import p_map
from tqdm import tqdm
import os
import pickle
from itertools import islice
from functools import partial
import pandas as pd
from info_gain import info_gain
import numpy as np

def computeInformationGain(imports):
    labels = imports.loc['benign']
    imports = imports.drop('benign')
    retDict = pd.DataFrame(0.0,index=imports.index,columns=['IG'])
    for imp,row in imports.iterrows():
        retDict.at[imp,'IG'] = info_gain.info_gain(labels,row)
    return retDict

def createChunks(data, SIZE=500):
    it = iter(data)
    for i in range(0, len(data), SIZE):
        yield {k:data[k] for k in islice(it, SIZE)}

def dfIG(sha1s, topDLLs, topAPIs):
    dfDLLsIG = pd.DataFrame(True,index=topDLLs,columns=sha1s)
    dfAPIsIG = pd.DataFrame(True,index=topAPIs,columns=sha1s)
    for sha1,dictionary in sha1s.items():
        #Merge top dlls and apis
        consideredDLLs = set(sha1s[sha1]['dlls']) & topDLLs
        consideredAPIs = set(sha1s[sha1]['imps']) & topAPIs

        #Mark top dlls and apis
        extractedDLLs = pd.Series(False,index=topDLLs)
        extractedAPIs = pd.Series(False,index=topAPIs)

        for consideredDLL in consideredDLLs:
            extractedDLLs[consideredDLL] = True
        dfDLLsIG[sha1] = extractedDLLs

        for consideredAPI in consideredAPIs:
            extractedAPIs[consideredAPI] = True
        dfAPIsIG[sha1] = extractedAPIs
    return dfDLLsIG, dfAPIsIG

def top_imports(plot,binary,experiment):
    sha1s = config.getList(experiment,validation=True,binary=binary)
    samplesLen = len(sha1s)
    print("Extracting imports (DLL and APIs) from all the {} samples in the validation set".format(samplesLen))
    allSamplesImports = p_map(imports.extract, sha1s, num_cpus=config.CORES)
    allSamplesImports = {k:v for d in allSamplesImports for k,v in d.items()}

    #Checking problems with extraction
    problematicSha1s = {k:v for k,v in allSamplesImports.items() if v['error']}
    config.updateLabelDataFrame(experiment,problematicSha1s)
    allSamplesImports = {k:v for k,v in allSamplesImports.items() if not v['error']}

    #Computing frequency 
    print("Computing DLLs and APIs prevalence")
    topDLLs = Counter()
    topAPIs = Counter()
    for sha1,content in allSamplesImports.items():
        topDLLs.update(content['dlls'])
        topAPIs.update(content['imps'])
    print("Total number of unique DLLs is: {}".format(len(topDLLs.keys())))
    print("Total number of unique APIs is: {}".format(len(topAPIs.keys())))

    #Saving for plot
    if plot:
        print("Saving complete list for CCDF plot")
        filepath = os.path.join(config.PLOTS_DIRECTORY,experiment,'dlls_count.pickle')
        with open(filepath, 'wb') as wFile:
            pickle.dump(topDLLs,wFile)
        filepath = os.path.join(config.PLOTS_DIRECTORY,experiment,'apis_count.pickle')
        with open(filepath, 'wb') as wFile:
            pickle.dump(topAPIs,wFile)

    #Filtering the most and least common
    print("Filtering the most and least common")
    upperBound = int(len(allSamplesImports) - len(allSamplesImports)*.1/100)
    lowerBound = int(len(allSamplesImports)*.1/100)
    topDLLs = set([k for k,v in topDLLs.items() if v>lowerBound and v <upperBound])
    topAPIs = set([k for k,v in topAPIs.items() if v>lowerBound and v <upperBound])

    print("Computing Information Gain")
    partialDfIG = partial(dfIG,topDLLs=topDLLs,topAPIs=topAPIs)
    chunks = []
    for chunk in createChunks(allSamplesImports,500):
        chunks.append(chunk)

    results = p_map(partialDfIG,chunks)

    dfDLLsIG = []
    dfAPIsIG = []
    for partial_dfDLLsIG,partial_dfAPIsIG in results:
        dfDLLsIG.append(partial_dfDLLsIG)
        dfAPIsIG.append(partial_dfAPIsIG)

    dfDLLsIG = pd.concat(dfDLLsIG,axis=1)
    dfAPIsIG = pd.concat(dfAPIsIG,axis=1)

    labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY,experiment,'labels.pickle'))
    if binary:
        dfDLLsIG.loc['benign',dfDLLsIG.columns] = labels.loc[dfDLLsIG.columns,'benign']
        dfAPIsIG.loc['benign',dfAPIsIG.columns] = labels.loc[dfAPIsIG.columns,'benign']
    else:
        dfDLLsIG.loc['benign',dfDLLsIG.columns] = labels.loc[dfDLLsIG.columns,'family']
        dfAPIsIG.loc['benign',dfAPIsIG.columns] = labels.loc[dfAPIsIG.columns,'family']

    IGDLLs = computeInformationGain(dfDLLsIG)
    IGAPIs = computeInformationGain(dfAPIsIG)

    #Render in matplotlib
    if plot:
        print("Saving DLLs IG for CCDF plot")
        filepath = os.path.join(config.PLOTS_DIRECTORY,experiment,'dlls_ig.pickle')
        IGDLLs.to_pickle(filepath)
        print("Saving APIs IG for CCDF plot")
        filepath = os.path.join(config.PLOTS_DIRECTORY,experiment,'apis_ig.pickle')
        IGAPIs.to_pickle(filepath)

    # igThresh = input("Which IG value do you want to cut DLLs?")
    # #Multiclass value
    # igThresh = 0.0152
    # #Binary value
    # igThresh = 0.0008
    # IGDLLs  = IGDLLs[IGDLLs.IG>=float(igThresh)].index
    IGDLLs  = IGDLLs.index
    
    filepath = os.path.join(config.SELECT_DIRECTORY,experiment,'dlls.list')
    with open(filepath,'w') as wFile:
        wFile.write("\n".join(IGDLLs))

    # igThresh = input("Which IG value do you want to cut APIs?")
    # #Multiclass value
    # igThresh = 0.015
    # #Binary value
    # igThresh = 0.0006
    # IGAPIs  = IGAPIs[IGAPIs.IG>=float(igThresh)].index

    IGAPIs  = IGAPIs.sort_values(by='IG',ascending=False)
    IGAPIs  = IGAPIs.head(4500)
    IGAPIs  = IGAPIs.index
    
    filepath = os.path.join(config.SELECT_DIRECTORY,experiment,'apis.list')
    with open(filepath,'w') as wFile:
        wFile.write("\n".join(IGAPIs))
