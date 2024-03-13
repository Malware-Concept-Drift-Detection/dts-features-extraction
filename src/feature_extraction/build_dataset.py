import os
import pickle
import re
import subprocess
import time
from functools import partial
import pandas as pd
import tqdm
from p_tqdm import p_map
from src.feature_extraction import config
import src.feature_extraction.extract_features as ef


def BAK_enrich_features(raw):
    STD_SECTIONS = ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls']
    columns = [c for c in raw.columns if re.match('^pesection_[0-9]{1,2}_name$', c)]
    columns.append('pesectionProcessed_entrypointSection_name')
    to_drop = []
    for column in columns:
        column_exists = column + '_exists'
        column_is_standard = column + '_isStandard'
        raw[column_exists] = raw[column].map(lambda x: True if x != 'none' else False)
        raw[column_is_standard] = raw[column].map(
            lambda x: True if x in STD_SECTIONS else False if x != 'none' else False)
        to_drop.append(column)
    raw = raw.drop(to_drop, axis=1)
    return raw


def enrich_features(raw):
    STD_SECTIONS = ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls']
    to_drop = []
    to_append = []
    for i_column in range(1, 98):
        column = f'pesection_{i_column}_name'
        how_many = len(set(raw[column]))
        column_exists = f'pesection_{i_column}_exists'
        column_is_standard = f'pesection_{i_column}_isStandard'
        raw[column_exists] = raw[column].map(lambda x: True if x != 'none' else False)
        raw[column_is_standard] = raw[column].map(
            lambda x: True if x in STD_SECTIONS else False if x != 'none' else False)
        to_drop.append(column)

    raw = raw.drop(to_drop, axis=1)
    return raw


def STANDARD_enrich_features(raw):
    STD_SECTIONS = ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls']
    to_drop = []
    to_append = []
    for i_column in range(1, 98):
        column = f'pesection_{i_column}_name'
        how_many = len(set(raw[column]))
        if how_many < 25:
            to_drop.extend([x for x in raw.columns if re.match(f'^pesection_{i_column}_', x)])
        else:
            column_exists = f'pesection_{i_column}_exists'
            column_is_standard = f'pesection_{i_column}_isStandard'
            raw[column_exists] = raw[column].map(lambda x: True if x != 'none' else False)
            raw[column_is_standard] = raw[column].map(
                lambda x: True if x in STD_SECTIONS else False if x != 'none' else False)
            to_drop.append(column)

    raw = raw.drop(to_drop, axis=1)

    to_drop = []
    columns = [c for c in raw.columns if re.match('^pesection', c)]
    for column in columns:
        how_many = len(set(raw[column]))
        if how_many == 1:
            to_drop.append(column)
    raw = raw.drop(to_drop, axis=1)
    return raw


def build_dataset(binary, N, experiment, sha_list=None):
    # Read all Section Features for padding

    with open(os.path.join('PRE_topFeatures', 'all_sections.list'), 'r') as sectionFile:
        all_sections = {k: v for k, v in (l.split('\t') for l in sectionFile.read().splitlines())}
    # Read most common DLLs
    with open(os.path.join('PRE_topFeatures', experiment, 'dlls.list'), 'r') as dllFile:
        top_DLLs = set(dllFile.read().splitlines())
    # Read most common Imports
    with open(os.path.join('PRE_topFeatures', experiment, 'apis.list'), 'r') as importsFile:
        top_imports = set(importsFile.read().splitlines())
    # Read most common Strings
    with open(os.path.join('PRE_topFeatures', experiment, 'strings.list'), 'r') as stringsFile:
        top_strings = set(stringsFile.read().splitlines())
    # Read most common N_grams
    with open(os.path.join('PRE_topFeatures', experiment, 'nGrams.list'), 'r') as N_gramFile:
        top_n_grams = set(N_gramFile.read().splitlines())
    # Read most common Opcodes
    with open(os.path.join('PRE_topFeatures', experiment, 'trainTopOpcodesCounter.pickle'), 'rb') as opcodesFile:
        top_opcodes = pickle.load(opcodesFile)

    # For singleton
    sha1s = sha_list
    # sha1s = config.getList(experiment,trainTest=True,binary=binary)

    current_extracting_function = partial(ef.extract_features,
                                          N=N,
                                          genericsFlag=True,
                                          headersFlag=True,
                                          allSections=all_sections,
                                          topStrings=top_strings,
                                          topDlls=top_DLLs,
                                          topImports=top_imports,
                                          topN_grams=top_n_grams,
                                          topOpcodes=top_opcodes
                                          )

    start = time.time()  # those are seconds
    # Split into chunks
    c_len = 15 * config.CORES
    chunks = [sha1s[i:i + c_len] for i in range(0, len(sha1s), c_len)]

    # Start computation
    for index, chunk in enumerate(chunks):
        print("Round {}/{}".format(index, len(chunks)))
        results = p_map(current_extracting_function, chunk, num_cpus=config.CORES)
        # problematicSha1s = [y for x,y in results if not x]
        # problematicSha1s = {k:v for d in problematicSha1s for k,v in d.items()}
        # config.updateLabelDataFrame(experiment,problematicSha1s)
        results = [y for x, y in results if x]
        dataset = pd.DataFrame(results).set_index('sample_hash')
        dataset.to_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'chunk_{}.pickle'.format(index)))

    print(f"Merging all the {len(chunks)} pieces...")
    dataset_pieces = []
    for index in tqdm.tqdm(range(0, len(chunks))):
        dataset_pieces.append(
            pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'chunk_{}.pickle'.format(index))))
    dataset = pd.concat(dataset_pieces)

    # Convert section names in features that indicate whether the section exists and has a standard name
    dataset = enrich_features(dataset)

    # We are done
    end = time.time()  # those are seconds
    elapsed = int(end - start)
    print("It took {} minutes to create the dataset".format(elapsed / 60))
    print("Minimum extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.min()))
    print("Maximum extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.max()))
    print("Average extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.mean()))
    print("Standard Deviation on extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.std()))
    dataset.to_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'dataset.pickle'))

    # Remove temp
    for index in tqdm.tqdm(range(0, len(chunks))):
        remove = os.path.join(config.DATASET_DIRECTORY, experiment, 'chunk_{}.pickle'.format(index))
        subprocess.call('rm {}'.format(remove), shell=True)
