import os
import subprocess

import pandas as pd

from src.feature_extraction import config


def evaluate_agreement(output, family):
    if len(output) != 1:
        raise Exception
    agreement = dict(item.split(":") for item in output[0].split(","))
    tot = sum([int(x) for x in agreement.values()])
    return round(100 * int(agreement[family]) / tot, 2)


def create_symbolic(df):
    _, df = df
    for sample, row in df.iterrows():
        subprocess.call(
            f"mkdir -p dataset/toSync/{row['family']} && "
            f"ln -s {config.MALWARE_DIRECTORY}{row['family']}/{sample} dataset"
            f"/toSync/{row['family']}/{sample}",
            shell=True)


def update_label_data_frame(experiment, sample_list):
    filepath = os.path.join(config.DATASET_DIRECTORY, experiment, 'labels.pickle')
    dataset = pd.read_pickle(filepath)
    for sample, dictionary in sample_list.items():
        dataset.at[sample, 'error'] = dictionary['error']
    dataset.to_pickle(filepath)


def get_list(experiment, train_test=False, validation=False, binary=False, max_size=-1):
    dataset = pd.read_csv(os.path.join(experiment, DATASET_DIRECTORY, 'sha256_family.csv'))
    if not binary:
        dataset = dataset[~dataset.benign]
    sha1s = []
    if train_test:
        sha1s.append(dataset[dataset.set == 'trainTest'])
    if validation:
        sha1s.append(dataset[dataset.set == 'validation'])
    return_df = pd.concat(sha1s)

    if max_size > 0:
        return_df = return_df[return_df.mb <= max_size]

    return_df = return_df[return_df.error.str.len() == 0]
    t_list = list(zip(return_df.index, return_df.family))
    return t_list


def split(to_split):
    splitting = {'trainTest': .80, 'validation': .20}
    groups = to_split.groupby(['family', 'benign'])
    for _, df in groups:
        l = list(df.index)
        samples = len(l)
        for spl_set, perc in splitting.items():
            select = samples * perc
            if select > len(l):
                select = len(l)
            current = random.sample(l, math.ceil(select))
            to_split.loc[current, 'set'] = spl_set
            l = [x for x in l if x not in current]
    return to_split
