from src.feature_extraction import config
from src.feature_extraction.F_strings import strings
from collections import Counter
from p_tqdm import p_map
from tqdm import tqdm
import os
import pickle


def top_strings(plot, binary, experiment):
    sha1s = config.getList(experiment, validation=True, binary=binary)
    samplesLen = len(sha1s)
    print("Extracting strings from all the samples in the validation set")
    allSamplesStrings = p_map(strings.extract, sha1s, num_cpus=config.CORES)

    # Computing strings frequecy
    # (unique strings per binary so this means that if a string appears more than once
    # in the binary it is counted only once)
    print("Computing string prevalence")
    topStrings = Counter()
    for sampleStrings in tqdm(allSamplesStrings):
        topStrings.update(set(sampleStrings))  # Set is important here for the frequency
    print("Total number of unique strings is: {}".format(len(topStrings.keys())))
    import IPython
    IPython.embed(colors='Linux')

    # Compute percentages
    print("Computing percentages and filtering")
    topStringsPercentages = Counter()
    for topStringKey, topStringPrevalence in tqdm(topStrings.items()):
        topStringsPercentages[topStringKey] = topStringPrevalence / samplesLen

    # Fix thresholds:    we select 0.01 of the strings (discard 99.99% of them)
    #                   check how many times those strings appear (at least)
    #                   check in how many samples they appear
    threshold = int(len(topStrings) * 0.0001)
    topStringsReduced = topStrings.most_common(threshold)
    topStringsPercentagesReduced = topStringsPercentages.most_common(threshold)
    seenInLessThan = topStringsReduced[-1][1]
    seenInLessThanPercentage = topStringsPercentagesReduced[-1][1] * 100

    print("Selected strings: {}".format(len(topStringsReduced)))
    print("99.99% of the strings are seen in less than {} samples".format(seenInLessThan))
    print("99.99% of the strings are seen in less than {}% of the samples".format(seenInLessThanPercentage))

    # Save topStrings
    filepath = os.path.join(config.SELECT_DIRECTORY, experiment, 'strings.list')
    with open(filepath, 'w') as wFile:
        wFile.write("\n".join(['str_' + s for s, _ in topStringsReduced]))

    # Save for matplotlib
    if plot:
        print("Saving strings for CCDF ")
        filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'strings_count.pickle')
        with open(filepath, 'wb') as wFile:
            pickle.dump(topStrings, wFile)
