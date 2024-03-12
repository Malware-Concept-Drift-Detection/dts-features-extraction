import os
import time
import F_generics.generics as generics
import F_headers.headers as headers
import F_sections.sections as sections
import F_imports.imports as imports
import F_N_grams.ngrams as ngrams
import F_opcodes.opcodes as opcodes
import F_strings.strings as strings
import config
import pickle


def extractFeatures(sha1_family, N, genericsFlag=False, headersFlag=False, allSections=None, topDlls=None,
                    topImports=None, topStrings=None, topN_grams=None, topOpcodes=None):
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
        if genericsFlag:
            extractedGenerics = generics.extract(filepath)
            row.update(extractedGenerics)

        # Headers features
        if headersFlag:
            extractedHeaders = headers.extract(filepath)
            row.update(extractedHeaders)

        # Section features
        if allSections:
            extractedSections = sections.extract(filepath, allSections)
            row.update(extractedSections)

        # DLLs and Imports features
        if topDlls and topImports:
            extractedDlls, extractedImports = imports.extractAndPad(filepath, topDlls, topImports)
            row.update(extractedDlls)
            row.update(extractedImports)

        # Strings features
        if topStrings:
            extractedStrings = strings.extractAndPad(filepath, topStrings)
            row.update(extractedStrings)

        # N_grams features
        if topN_grams:
            extractedN_grams = ngrams.extractAndPad(filepath, topN_grams)
            row.update(extractedN_grams)

        # Opcodes features
        if topOpcodes:
            extractedOpcodes = opcodes.extractAndPad(filepath, topOpcodes, N)
            row.update(extractedOpcodes)

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
    with open('./PRE_topFeatures/allSections.list', 'r') as sectionFile:
        allSections = {k: v for k, v in (l.split('\t') for l in sectionFile.read().splitlines())}
    # Read most common DLLs
    with open('./PRE_topFeatures/dlls.list', 'r') as dllFile:
        topDlls = set(dllFile.read().splitlines())
    # Read most common Imports
    with open('./PRE_topFeatures/apis.list', 'r') as importsFile:
        topImports = set(importsFile.read().splitlines())
    # Read most common Strings
    with open('./PRE_topFeatures/strings.list', 'r') as stringsFile:
        topStrings = set(stringsFile.read().splitlines())
    # Read most common N_grams
    with open('./PRE_topFeatures/nGrams.list', 'r') as N_gramFile:
        topN_grams = set(N_gramFile.read().splitlines())
    # Read most common Opcodes
    with open('./PRE_topFeatures/opcodes.pickle', 'rb') as opcodesFile:
        topOpcodes = pickle.load(opcodesFile)

    # This number represents the number of document for which the extraction of opcodes was successful
    N = 57048
    sha1s = config.getList(training=True, test=True, binary=False)
    extractFeatures(
        sha1s[0],
        N,
        # genericsFlag=True,
        # headersFlag=True,
        # allSections=allSections,
        # topStrings=topStrings,
        # topDlls=topDlls,
        # topImports=topImports,
        topN_grams=topN_grams,
        # topOpcodes=topOpcodes
    )
