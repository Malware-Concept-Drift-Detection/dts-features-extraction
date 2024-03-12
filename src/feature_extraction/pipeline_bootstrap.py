#!/usr/bin/env python3
import config
import os
import extractFeatures as ef
from collections import Counter
from p_tqdm import p_map
from functools import partial
import F_sections.sections as sections

def checkBroken():
    #Check those samples that fail the extraction of sections and opcodes
    check = []

    #Goodware
    goodware = os.listdir(config.GOODWARE_DIRECTORY)
    check.extend(zip(goodware,[None]*len(goodware)))

    #Malware
    families = os.listdir(config.MALWARE_DIRECTORY)
    for family in families:
        currentSamples = os.listdir(os.path.join(config.MALWARE_DIRECTORY,family))
        check.extend(zip(currentSamples,[family]*len(currentSamples)))

    #Check the maximum number of sections
    results = p_map(sections.getMaxSections,check,num_cpus=config.CORES)
    maxSections = max(results)

    #Generate allSections File
    with open(os.path.join('PRE_topFeatures','sectionProcessedTemplate'),'r') as rFile:
        sectionTemplateProcessed = rFile.read().splitlines()
    with open(os.path.join('PRE_topFeatures','sectionTemplate'),'r') as rFile:
        sectionTemplate = rFile.read().splitlines()

    toWrite = sectionTemplateProcessed.copy()
    for section in range(1,maxSections+1):
        toWrite.extend([f'pesection_{section}_{x}' for x in sectionTemplate])

    with open(os.path.join('PRE_topFeatures','allSections.list'),'w') as wFile:
        wFile.write("\n".join(toWrite))

    #TOP Sections needed
    with open(os.path.join('PRE_topFeatures','allSections.list'),'r') as sectionFile:
        allSections = {k:v for k,v in (l.split('\t') for l in sectionFile.read().splitlines())}

    #Fake TOP Opcodes needed
    topOpcodes = {'add':1}
    topOpcodes = Counter(topOpcodes)

    currentExtractingFunction = partial(ef.extractFeatures,
            N=10000,
            genericsFlag=False,
            headersFlag=False,
            allSections=allSections,
            topStrings=None,
            topDlls=None,
            topImports=None,
            topN_grams=None,
            topOpcodes=topOpcodes
            )

    print(f'Looking for broken files...')
    # check = ('f5c009839a21f89a74b7d86e7957856401589d1c02d0f26e4a0d9e4409ee11de','cossta')
    # currentExtractingFunction(check)
    results = p_map(currentExtractingFunction,check,num_cpus=config.CORES)
    problematicSha1s = [y for x,y in results if not x]
    problematicSha1s = {k:v for d in problematicSha1s for k,v in d.items()}
    with open(os.path.join(config.DATASET_DIRECTORY,'staticFails'),'w') as wFile:
        for sample,dictionary in problematicSha1s.items():
            wFile.write(f'{sample}\t{dictionary["error"]}\n')

    print(f'{len(problematicSha1s)} broken files found...')
if __name__ == '__main__':
