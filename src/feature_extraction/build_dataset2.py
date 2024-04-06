import os
import pickle
import re
import subprocess
import time
from functools import partial
import pandas as pd
import tqdm
from p_tqdm import p_map

from src.feature_extraction.top_features.top_strings import create_chunks
from src.feature_extraction.config import TOP_FEATURES_SUBDIR
from src.feature_extraction import config
from src.feature_extraction.extract_features import extract_features
from multiprocessing import Pool


def enrich_features(df):
    STD_SECTIONS = ['.text', '.data', '.rdata', '.idata', '.edata', '.rsrc', '.bss', '.crt', '.tls']
    to_drop = []
    for i_column in range(1, 17):
        column = f'pesection_{i_column}_name'
        column_exists = f'pesection_{i_column}_exists'
        column_is_standard = f'pesection_{i_column}_isStandard'
        df[column_exists] = df[column].map(lambda x: True if x != 'none' else False)
        df[column_is_standard] = df[column].map(
            lambda x: True if x in STD_SECTIONS else False if x != 'none' else False)
        to_drop.append(column)
    df = df.drop(to_drop, axis=1)
    return df


def build_dataset(N, experiment, malware_dataset):
    # # Read all Section Features for padding
    # with open(os.path.join(experiment, TOP_FEATURES_SUBDIR, 'all_sections.list'), 'r') as sectionFile:
    #     all_sections = {k: v for k, v in (l.split('\t') for l in sectionFile.read().splitlines())}
    # # Read most common DLLs
    # with open(os.path.join(experiment, TOP_FEATURES_SUBDIR, 'dlls.list'), 'r') as dllFile:
    #     top_DLLs = set(dllFile.read().splitlines())
    # # Read most common Imports
    # with open(os.path.join(experiment, TOP_FEATURES_SUBDIR, 'apis.list'), 'r') as importsFile:
    #     top_imports = set(importsFile.read().splitlines())
    # # Read most common Strings
    # with open(os.path.join(experiment, TOP_FEATURES_SUBDIR, 'strings.list'), 'r') as stringsFile:
    #     top_strings = set(stringsFile.read().splitlines())
    # # Read most common N_grams
    # with open(os.path.join(experiment, TOP_FEATURES_SUBDIR, 'ngrams.list'), 'r') as N_gramFile:
    #     top_n_grams = set(N_gramFile.read().splitlines())
    # # Read most common Opcodes
    # with (open(os.path.join(experiment, TOP_FEATURES_SUBDIR, 'opcodes.pickle'), 'rb')
    #       as opcodesFile):
    #     top_opcodes = pickle.load(opcodesFile)
    #
    # For singleton
    sha1s = malware_dataset.df_malware_family_fsd[['sha256', 'family']].to_numpy()

    # current_extracting_function = partial(extract_features,
    #                                       N=N,
    #                                       experiment=experiment,
    #                                       generics_flag=True,
    #                                       headers_flag=True,
    #                                       all_sections=all_sections,
    #                                       top_strings=top_strings,
    #                                       top_dlls=top_DLLs,
    #                                       top_imports=top_imports,
    #                                       top_ngrams=top_n_grams,
    #                                       top_opcodes=top_opcodes
    #                                       )
    #
    # # Split into chunks
    # c_len = 15 * 16
    # chunks = [sha1s[i:i + c_len] for i in range(0, len(sha1s), c_len)]
    #
    # exclude_shas = []
    # for index, chunk in enumerate(chunks):
    #     if index <= 201:
    #         shas = [x for x, y in chunk]
    #         exclude_shas = exclude_shas + shas
    #
    # sha1s = malware_dataset.df_malware_family_fsd
    # sha1s = sha1s[~sha1s["sha256"].isin(exclude_shas)]
    # sha1s = sha1s[['sha256', 'family']].to_numpy()
    #
    # Split into chunks
    # c_len = 15 * config.CORES
    # chunks = [sha1s[i:i + c_len] for i in range(0, len(sha1s), c_len)]
    #
    # for index, chunk in enumerate(chunks):
    #     if index >= 120:
    #         print(f"Round {index}/{len(chunks)}", flush=True)
    #         with Pool(1 if index == 120 else config.CORES) as p:
    #             results = p.map(current_extracting_function, chunk)
    #         dataset = pd.DataFrame(results).set_index('sample_hash')
    #         dataset.to_pickle(str(os.path.join(experiment, config.DATASET_DIRECTORY,
    #                                            f'chunk_{index}_1.pickle')))

    chunks_id = [f'chunk_{i}_1.pickle' for i in range(120)]
    chunks_id = chunks_id + [f'chunk_{i}.pickle' for i in range(202)]

    print(f"Merging all the {len(chunks_id)} pieces...")
    dataset_pieces = []
    for f_name in tqdm.tqdm(chunks_id):
        dataset_pieces.append(
            pd.read_pickle(str(
                os.path.join(experiment, f_name))
            )
        )
    dataset = pd.concat(dataset_pieces)

    # Convert section names in features that indicate whether the section exists and has a standard name
    dataset = enrich_features(dataset)

    print("Minimum extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.min()))
    print("Maximum extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.max()))
    print("Average extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.mean()))
    print("Standard Deviation on extraction time is {:.2f} milliseconds".format(dataset.ms_elapsed.std()))
    dataset.to_pickle(os.path.join(experiment,  'dataset3.pickle'))

    # # Remove temp
    # for i in tqdm.tqdm(range(0, len(chunks))):
    #     remove = os.path.join(experiment, config.DATASET_DIRECTORY, 'chunk_{}.pickle'.format(i))
    #     subprocess.call('rm {}'.format(remove), shell=True)

