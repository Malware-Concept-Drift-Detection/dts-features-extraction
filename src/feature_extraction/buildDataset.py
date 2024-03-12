#!/usr/bin/env python3
import re
import time
import sys
import extractFeatures as ef
import multiprocessing as mp
import os
from p_tqdm import p_map
import pandas as pd
import numpy as np
import config
import pickle
from functools import partial
import math
import tqdm
import subprocess
from collections import Counter

def BAKenrichFeatures(raw):
    STD_SECTIONS = ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls']
    columns = [c for c in raw.columns if re.match('^pesection_[0-9]{1,2}_name$',c)]
    columns.append('pesectionProcessed_entrypointSection_name')
    toDrop = []
    for column in columns:
        columnExists = column+'_exists'
        columnIsStandard = column+'_isStandard'
        raw[columnExists] = raw[column].map(lambda x: True if x != 'none' else False )
        raw[columnIsStandard] = raw[column].map(lambda x: True if x in STD_SECTIONS else False if x != 'none' else False)
        toDrop.append(column)
    raw = raw.drop(toDrop,axis=1)
    return raw

def enrichFeatures(raw):
    STD_SECTIONS = ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls']
    toDrop = []
    toAppend = []
    for i_column in range(1,98):
        column = f'pesection_{i_column}_name' 
        howMany = len(set(raw[column]))
        columnExists = f'pesection_{i_column}_exists'
        columnIsStandard = f'pesection_{i_column}_isStandard'
        raw[columnExists] = raw[column].map(lambda x: True if x != 'none' else False )
        raw[columnIsStandard] = raw[column].map(lambda x: True if x in STD_SECTIONS else False if x != 'none' else False)
        toDrop.append(column)

    raw = raw.drop(toDrop,axis=1)
    return raw

def STANDARDenrichFeatures(raw):
    STD_SECTIONS = ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls']
    toDrop = []
    toAppend = []
    for i_column in range(1,98):
        column = f'pesection_{i_column}_name' 
        howMany = len(set(raw[column]))
        if howMany<25:
            toDrop.extend([x for x in raw.columns if re.match(f'^pesection_{i_column}_',x)])
        else:
            columnExists = f'pesection_{i_column}_exists'
            columnIsStandard = f'pesection_{i_column}_isStandard'
            raw[columnExists] = raw[column].map(lambda x: True if x != 'none' else False )
            raw[columnIsStandard] = raw[column].map(lambda x: True if x in STD_SECTIONS else False if x != 'none' else False)
            toDrop.append(column)

    raw = raw.drop(toDrop,axis=1)

    toDrop = []
    columns = [c for c in raw.columns if re.match('^pesection',c)]
    for column in columns:
        howMany = len(set(raw[column]))
        if howMany==1:
            toDrop.append(column)
    raw = raw.drop(toDrop,axis=1)
    return raw

def buildDataset(binary,N,experiment,shaList=None):
    #Read all Section Features for padding
    
    with open(os.path.join('PRE_topFeatures','allSections.list'),'r') as sectionFile:
        allSections = {k:v for k,v in (l.split('\t') for l in sectionFile.read().splitlines())}
    #Read most common DLLs
    with open(os.path.join('PRE_topFeatures',experiment,'dlls.list'),'r') as dllFile:
        topDlls = set(dllFile.read().splitlines())
    #Read most common Imports
    with open(os.path.join('PRE_topFeatures',experiment,'apis.list'),'r') as importsFile:
        topImports = set(importsFile.read().splitlines())
    #Read most common Strings
    with open(os.path.join('PRE_topFeatures',experiment,'strings.list'),'r') as stringsFile:
        topStrings = set(stringsFile.read().splitlines())
    #Read most common N_grams
    with open(os.path.join('PRE_topFeatures',experiment,'nGrams.list'),'r') as N_gramFile:
        topN_grams = set(N_gramFile.read().splitlines())
    #Read most common Opcodes
    with open(os.path.join('PRE_topFeatures',experiment,'trainTopOpcodesCounter.pickle'),'rb') as opcodesFile:
        topOpcodes = pickle.load(opcodesFile)
    
    #For singleton
    sha1s = shaList
    # sha1s = config.getList(experiment,trainTest=True,binary=binary)


    currentExtractingFunction = partial(ef.extractFeatures,
            N=N,
            genericsFlag=True,
            headersFlag=True,
            allSections=allSections,
            topStrings=topStrings,
            topDlls=topDlls,
            topImports=topImports,
            topN_grams=topN_grams,
            topOpcodes=topOpcodes
            )

    start = time.time() #those are seconds
    #Split into chunks
    cLen = 15*config.CORES
    chunks = [sha1s[i:i + cLen] for i in range(0, len(sha1s), cLen)]

    #Start computation
    for index,chunk in enumerate(chunks):
        print("Round {}/{}".format(index,len(chunks)))
        results = p_map(currentExtractingFunction,chunk,num_cpus=config.CORES)
        # problematicSha1s = [y for x,y in results if not x]
        # problematicSha1s = {k:v for d in problematicSha1s for k,v in d.items()}
        # config.updateLabelDataFrame(experiment,problematicSha1s)
        results = [y for x,y in results if x]
        dataset = pd.DataFrame(results).set_index('sample_hash')
        dataset.to_pickle(os.path.join(config.DATASET_DIRECTORY,experiment,'chunk_{}.pickle'.format(index)))

    print(f"Merging all the {len(chunks)} pieces...") 
    datasetPieces = []
    for index in tqdm.tqdm(range(0,len(chunks))):
        datasetPieces.append(pd.read_pickle(os.path.join(config.DATASET_DIRECTORY,experiment,'chunk_{}.pickle'.format(index))))
    dataset = pd.concat(datasetPieces) 

    #Convert section names in features that indicate whether the section exists and has a standard name
    dataset = enrichFeatures(dataset)

    # We are done
    end = time.time() #those are seconds
    elapsed = int(end-start)
    print("It took {} minutes to create the dataset".format(elapsed/60)) 
    print("Minimum extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.min())) 
    print("Maximum extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.max())) 
    print("Average extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.mean())) 
    print("Standard Deviation on extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.std())) 
    dataset.to_pickle(os.path.join(config.DATASET_DIRECTORY,experiment,'dataset.pickle'))

    # Remove temp
    for index in tqdm.tqdm(range(0,len(chunks))):
        remove = os.path.join(config.DATASET_DIRECTORY,experiment,'chunk_{}.pickle'.format(index))
        subprocess.call('rm {}'.format(remove), shell=True)
