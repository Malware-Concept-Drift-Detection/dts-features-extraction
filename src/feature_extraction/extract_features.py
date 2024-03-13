import os
import time
import src.feature_extraction.static.generics as generics
import src.feature_extraction.static.headers as headers
import src.feature_extraction.static.sections as sections
import src.feature_extraction.static.imports as imports
import src.feature_extraction.static.ngrams as ngrams
import src.feature_extraction.static.opcodes as opcodes
import src.feature_extraction.static.strings as strings
from src.feature_extraction import config
import pickle


def extract_features(sha1_family, N, generics_flag=False, headers_flag=False, all_sections=None, top_DLLs=None,
                     top_imports=None, top_strings=None, top_n_grams=None, top_opcodes=None):
    # Singleton
    filepath = os.path.join(config.MALWARE_DIRECTORY, sha1_family)
    sha1 = sha1_family

    # #Restore the following
    # sha1,family = sha1_family
    # if family:
    #     filepath = os.path.join(config.MALWARE_DIRECTORY,family,sha1)
    # else:
    #     filepath = os.path.join(config.GOODWARE_DIRECTORY,sha1)
    # Row is a dictionary with sample hash and then all the features as key:value
    row = dict()
    row['sample_hash'] = sha1

    # Get init time
    start = time.time() * 1000

    try:
        # Generic features
        if generics_flag:
            extracted_generics = generics.extract(filepath)
            row.update(extracted_generics)

        # Headers features
        if headers_flag:
            extracted_headers = headers.extract(filepath)
            row.update(extracted_headers)

        # Section features
        if all_sections:
            extracted_sections = sections.extract(filepath, all_sections)
            row.update(extracted_sections)

        # DLLs and Imports features
        if top_DLLs and top_imports:
            extracted_dlls, extracted_imports = imports.extract_and_pad(filepath, top_DLLs, top_imports)
            row.update(extracted_dlls)
            row.update(extracted_imports)

        # Strings features
        if top_strings:
            extracted_strings = strings.extract_and_pad(filepath, top_strings)
            row.update(extracted_strings)

        # N_grams features
        if top_n_grams:
            extracted_n_grams = ngrams.extract_and_pad(filepath, top_n_grams)
            row.update(extracted_n_grams)

        # Opcodes features
        if top_opcodes:
            extracted_opcodes = opcodes.extract_and_pad(filepath, top_opcodes, N)
            row.update(extracted_opcodes)

        # Get end time
        end = time.time() * 1000
        elapsed = int(end - start)
        row['ms_elapsed'] = elapsed
        return True, row

    except Exception as e:
        print(e)
        return False, {sha1: {'error': e}}


if __name__ == '__main__':
    # Read all Section Features for padding
    with open('./PRE_topFeatures/allSections.list', 'r') as section_file:
        all_sections = {k: v for k, v in (l.split('\t') for l in section_file.read().splitlines())}
    # Read most common DLLs
    with open('./PRE_topFeatures/dlls.list', 'r') as dll_file:
        top_dlls = set(dll_file.read().splitlines())
    # Read most common Imports
    with open('./PRE_topFeatures/apis.list', 'r') as imports_file:
        top_imports = set(imports_file.read().splitlines())
    # Read most common Strings
    with open('./PRE_topFeatures/strings.list', 'r') as strings_file:
        top_strings = set(strings_file.read().splitlines())
    # Read most common N_grams
    with open('./PRE_topFeatures/nGrams.list', 'r') as n_gram_file:
        top_n_grams = set(n_gram_file.read().splitlines())
    # Read most common Opcodes
    with open('./PRE_topFeatures/opcodes.pickle', 'rb') as opcodes_file:
        top_opcodes = pickle.load(opcodes_file)

    # This number represents the number of document for which the extraction of opcodes was successful
    N = 57048
    sha1s = config.get_list(training=True, test=True, binary=False)
    extract_features(
        sha1s[0],
        N,
        generics_flag=True,
        headers_flag=True,
        all_sections=all_sections,
        top_strings=top_strings,
        top_DLLs=top_dlls,
        top_imports=top_imports,
        top_n_grams=top_n_grams,
        top_opcodes=top_opcodes
    )
