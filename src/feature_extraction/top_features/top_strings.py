from itertools import islice

import numpy as np
from tqdm import tqdm

from src.dataset.setup_dataset import malware_dataset
from src.feature_extraction import config
from src.feature_extraction.static.strings import StringsExtractor
from collections import Counter
from multiprocessing import Pool
from p_tqdm import p_map
# from tqdm import tqdm
import os
import IPython


def create_chunks(data, size=12):
    n = round(len(data) / size)
    return [data[i * n: (i + 1) * n] if i < size - 1 else data[i * n:] for i in range(size)]


def top_strings(experiment):
    sha1s = malware_dataset.training_dataset[['sha256', 'family']].to_numpy()
    #sha1s = sha1s[sha1s["family"] == "mocrt"].to_numpy()
    samples_len = len(sha1s)
    print("Extracting strings from all the samples in the training set")
    strings_extractor = StringsExtractor()

    chunks = create_chunks(sha1s, config.CORES)
    print([len(chunk) for chunk in chunks])

    # print(np.array_equal(np.concatenate(chunks), sha1s)) -> True
    # with Pool(config.CORES) as p:
    #     all_samples_strings = p.map(strings_extractor.extract, chunks)

    all_samples_strings = p_map(strings_extractor.extract, chunks, num_cpus=config.CORES)

    # Computing strings frequency
    # (unique strings per binary so this means that if a string appears more than once
    # in the binary it is counted only once)
    print("Computing string prevalence")
    top_strings = Counter()
    for sample_strings in all_samples_strings:
        top_strings.update(set(sample_strings))  # Set is important here for the frequency

    # print(top_strings)
    print("Total number of unique strings is: {}".format(len(top_strings.keys())))
    # IPython.embed(colors='Linux')

    # Compute percentages
    print("Computing percentages and filtering")
    top_strings_percentages = Counter()
    for top_string_key, top_string_prevalence in tqdm(top_strings.items()):
        top_strings_percentages[top_string_key] = top_string_prevalence / samples_len

    # Fix thresholds:    we select 0.01 of the strings (discard 99.99% of them)
    #                   check how many times those strings appear (at least)
    #                   check in how many samples they appear

    threshold = int(len(top_strings) * 0.0001)
    top_strings_reduced = top_strings.most_common(threshold)
    top_strings_percentages_reduced = top_strings_percentages.most_common(threshold)
    seen_in_less_than = top_strings_reduced[-1][1]
    seen_in_less_than_percentage = top_strings_percentages_reduced[-1][1] * 100

    print("Selected strings: {}".format(len(top_strings_reduced)))
    print("99.99% of the strings are seen in less than {} samples".format(seen_in_less_than))
    print("99.99% of the strings are seen in less than {}% of the samples".format(seen_in_less_than_percentage))

    # Save top_strings
    filepath = os.path.join(experiment, config.SELECT_DIRECTORY, 'strings.list')
    with open(filepath, 'w') as w_file:
        w_file.write("\n".join(['str_' + s for s, _ in top_strings_reduced]))

    # Save for matplotlib
    # if plot:
    #     print("Saving strings for CCDF ")
    #     filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'strings_count.pickle')
    #     with open(filepath, 'wb') as w_file:
    #         pickle.dump(top_strings, w_file)
