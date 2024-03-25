import pickle
import subprocess
from itertools import islice

import numpy as np
from tqdm import tqdm

from src.dataset.setup_dataset import MalwareDataset
from src.feature_extraction import config
from src.feature_extraction.static.strings import StringsExtractor
from collections import Counter
from multiprocessing import Pool
from p_tqdm import p_map
# from tqdm import tqdm
import os
import IPython


def create_chunks(data, size=12):
    data = [list(d) for d in data]
    n = round(len(data) / size)
    return [list(data[i * n: (i + 1) * n]) if i < size - 1 else list(data[i * n:]) for i in range(size)]


def top_strings(malware_dataset, experiment):
    sha1s = malware_dataset.training_dataset[['sha256', 'family']].head(100).to_numpy()
    # sha1s = sha1s[sha1s["family"].isin(fam)].to_numpy()
    samples_len = len(sha1s)
    print(f"Extracting strings from all the samples in the training set ({samples_len})")
    strings_extractor = StringsExtractor()

    # filename = "array.pickle"
    # if os.path.exists(filename):
    #     # Load the array from the file
    #     with open(filename, 'rb') as f:
    #         all_strings = pickle.load(f)
    # else:
    #
    #     with open(filename, 'wb') as f:
    #         pickle.dump(all_strings, f)

    # flatten = lambda l: [el for ll in l for el in ll]
    #chunks = create_chunks(sha1s, config.CORES)
    #p_map(strings_extractor.extract, sha1s, num_cpus=config.CORES)
    # Dump the array to a file

    # Computing strings frequency
    # (unique strings per binary so this means that if a string appears more than once
    # in the binary it is counted only once)
    print("Computing string prevalence")

    subprocess.call("cd ./tmp/strings/ && find ./sha1s/ -type f -exec cat {} +  > concat.txt", shell=True)
    subprocess.call(f"cd ./tmp/strings/ && sort concat.txt | uniq -c > strings_count.txt", shell=True)

    with open(f"./tmp/strings/strings_count.txt", "w", encoding="utf-8") as file:
        # Write each string of the array to a separate line in the file
        for line in file.readlines():
            print(line)

    # # top_strings = dict(all_strings[0])
    # # for strings_dict in all_strings[1:]:
    # #     strings_dict = dict(strings_dict)
    # #     for string in strings_dict:
    # #         if string in top_strings:
    # #             top_strings[string] += strings_dict[string]
    # #         else:
    # #             top_strings[string] = strings_dict[string]
    #
    # # Initialize an empty dictionary to store the counts
    # # top_strings = {}
    # # # Count occurrences of each string
    # # for string in all_strings:
    # #     if string in top_strings:
    # #         top_strings[string] += 1
    # #     else:
    # #         top_strings[string] = 1
    #
    # top_strings = Counter(all_strings)
    # for sample_strings in all_strings:
    #     top_strings.update(sample_strings)  # Set is important here for the frequency
    #
    # # print(top_strings)
    # print("Total number of unique strings is: {}".format(len(top_strings.keys())))
    # # IPython.embed(colors='Linux')
    #
    # # Compute percentages
    # print("Computing percentages and filtering")
    # top_strings_percentages = Counter()
    # for top_string_key, top_string_prevalence in tqdm(top_strings.items()):
    #     top_strings_percentages[top_string_key] = top_string_prevalence / samples_len
    #
    # # Fix thresholds:    we select 0.01 of the strings (discard 99.99% of them)
    # #                   check how many times those strings appear (at least)
    # #                   check in how many samples they appear
    #
    # threshold = int(len(top_strings) * 0.0001)
    # top_strings_reduced = top_strings.most_common(threshold)
    # top_strings_percentages_reduced = top_strings_percentages.most_common(threshold)
    # seen_in_less_than = top_strings_reduced[-1][1]
    # seen_in_less_than_percentage = top_strings_percentages_reduced[-1][1] * 100
    #
    # print("Selected strings: {}".format(len(top_strings_reduced)))
    # print("99.99% of the strings are seen in less than {} samples".format(seen_in_less_than))
    # print("99.99% of the strings are seen in less than {}% of the samples".format(seen_in_less_than_percentage))
    #
    # # Save top_strings
    # filepath = os.path.join(experiment, config.SELECT_DIRECTORY, 'strings.list')
    # with open(filepath, 'w') as w_file:
    #     w_file.write("\n".join(['str_' + s for s, _ in top_strings_reduced]))
