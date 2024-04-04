import os
import time

import pandas as pd

from src.feature_extraction.static.generics import GenericExtractor
from src.feature_extraction.static.headers import HeadersExtractor
from src.feature_extraction.static.sections import SectionsExtractor
from src.feature_extraction.static.imports import ImportsExtractor
from src.feature_extraction.static.ngrams import NGramsExtractor
from src.feature_extraction.static.opcodes import OpCodesExtractor
from src.feature_extraction.static.strings import StringsExtractor
from src.feature_extraction import config
import pickle


def extract_features(sha1_family, N, experiment=None, generics_flag=False, headers_flag=False, all_sections=None,
                     top_dlls=None, top_imports=None, top_strings=None, top_ngrams=None, top_opcodes=None):

    
    sha1, family = sha1_family
    filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
    # Row is a dictionary with sample hash and then all the features as key:value
    row = dict()
    row['sample_hash'] = sha1

    # Get init time
    start = time.time() * 1000
    # Generic features
    if generics_flag:
        extracted_generics = GenericExtractor().extract(filepath)
        row.update(extracted_generics)

    # Headers features
    if headers_flag:
        extracted_headers = HeadersExtractor().extract(filepath)
        row.update(extracted_headers)

    # Section features
    if all_sections:
        extracted_sections = SectionsExtractor().extract((filepath, all_sections))
        row.update(extracted_sections)

    # DLLs and Imports features
    if top_dlls and top_imports:
        extracted_dlls, extracted_imports = (ImportsExtractor()
                                                .extract_and_pad((filepath, top_dlls, top_imports)))
        row.update(extracted_dlls)
        row.update(extracted_imports)

    # Strings features
    if top_strings:
        extracted_strings = (StringsExtractor()
                                .extract_and_pad((filepath, top_strings)))
        row.update(extracted_strings)

    # N_grams features
    if top_ngrams:
        extracted_n_grams = (NGramsExtractor()
                                .extract_and_pad((filepath, top_ngrams)))
        row.update(extracted_n_grams)

    # Opcodes features
    if top_opcodes:
        extracted_opcodes = (OpCodesExtractor()
                                .extract_and_pad((filepath, top_opcodes, N)))
        row.update(extracted_opcodes)
    # Get end time
    end = time.time() * 1000
    elapsed = int(end - start)
    row['ms_elapsed'] = elapsed
    
    print(f"Done {sha1}", flush=True)
    return row

    

# print("Saving", flush=True)
# dataset = pd.DataFrame(rows).set_index('sample_hash')
# dataset.to_pickle(str(os.path.join(experiment, config.DATASET_DIRECTORY,
#                                     f'chunk_{i}.pickle')))
# print("Done process", flush=True)

