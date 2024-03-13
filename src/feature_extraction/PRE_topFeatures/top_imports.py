import os
import pickle
from collections import Counter
from functools import partial
from itertools import islice

from src.feature_extraction import config
from src.feature_extraction.F_imports import imports
import pandas as pd
from info_gain import info_gain
from p_tqdm import p_map


def compute_information_gain(imports):
    labels = imports.loc['benign']
    imports = imports.drop('benign')
    ret_dict = pd.DataFrame(0.0, index=imports.index, columns=['IG'])
    for imp, row in imports.iterrows():
        ret_dict.at[imp, 'IG'] = info_gain.info_gain(labels, row)
    return ret_dict


def create_chunks(data, size=500):
    it = iter(data)
    for i in range(0, len(data), size):
        yield {k: data[k] for k in islice(it, size)}


def df_IG(sha1s, top_DLLs, top_APIs):
    df_DLLS_IG = pd.DataFrame(True, index=top_DLLs, columns=sha1s)
    dfAPIsIG = pd.DataFrame(True, index=top_APIs, columns=sha1s)
    for sha1, dictionary in sha1s.items():
        # Merge top dlls and apis
        considered_DLLs = set(sha1s[sha1]['dlls']) & top_DLLs
        considered_APIs = set(sha1s[sha1]['imps']) & top_APIs

        # Mark top dlls and apis
        extracted_DLLs = pd.Series(False, index=top_DLLs)
        extracted_APIs = pd.Series(False, index=top_APIs)

        for considered_DLL in considered_DLLs:
            extracted_DLLs[considered_DLL] = True
        df_DLLS_IG[sha1] = extracted_DLLs

        for consideredAPI in considered_APIs:
            extracted_APIs[consideredAPI] = True
        dfAPIsIG[sha1] = extracted_APIs
    return df_DLLS_IG, dfAPIsIG


def top_imports(binary, experiment):
    sha1s = config.get_list(experiment, validation=True, binary=binary)
    samples_len = len(sha1s)
    print("Extracting imports (DLL and APIs) from all the {} samples in the validation set".format(samples_len))
    all_samples_imports = p_map(imports.extract, sha1s, num_cpus=config.CORES)
    all_samples_imports = {k: v for d in all_samples_imports for k, v in d.items()}

    # Checking problems with extraction
    problematic_sha1s = {k: v for k, v in all_samples_imports.items() if v['error']}
    config.update_label_data_frame(experiment, problematic_sha1s)
    all_samples_imports = {k: v for k, v in all_samples_imports.items() if not v['error']}

    # Computing frequency
    print("Computing DLLs and APIs prevalence")
    top_DLLs = Counter()
    top_APIs = Counter()
    for sha1, content in all_samples_imports.items():
        top_DLLs.update(content['dlls'])
        top_APIs.update(content['imps'])
    print("Total number of unique DLLs is: {}".format(len(top_DLLs.keys())))
    print("Total number of unique APIs is: {}".format(len(top_APIs.keys())))

    # Saving for plot
    # if plot:
    #     print("Saving complete list for CCDF plot")
    #     filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'dlls_count.pickle')
    #     with open(filepath, 'wb') as w_file:
    #         pickle.dump(top_DLLs, w_file)
    #     filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'apis_count.pickle')
    #     with open(filepath, 'wb') as w_file:
    #         pickle.dump(top_APIs, w_file)

    # Filtering the most and least common
    print("Filtering the most and least common")
    upper_bound = int(len(all_samples_imports) - len(all_samples_imports) * .1 / 100)
    lower_bound = int(len(all_samples_imports) * .1 / 100)
    top_DLLs = set([k for k, v in top_DLLs.items() if v > lower_bound and v < upper_bound])
    top_APIs = set([k for k, v in top_APIs.items() if v > lower_bound and v < upper_bound])

    print("Computing Information Gain")
    partial_df_IG = partial(df_IG, topDLLs=top_DLLs, topAPIs=top_APIs)
    chunks = []
    for chunk in create_chunks(all_samples_imports, 500):
        chunks.append(chunk)

    results = p_map(partial_df_IG, chunks)

    df_DLLs_IG = []
    df_APIs_IG = []
    for partial_dfDLLsIG, partial_dfAPIsIG in results:
        df_DLLs_IG.append(partial_dfDLLsIG)
        df_APIs_IG.append(partial_dfAPIsIG)

    df_DLLs_IG = pd.concat(df_DLLs_IG, axis=1)
    df_APIs_IG = pd.concat(df_APIs_IG, axis=1)

    labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'labels.pickle'))
    if binary:
        df_DLLs_IG.loc['benign', df_DLLs_IG.columns] = labels.loc[df_DLLs_IG.columns, 'benign']
        df_APIs_IG.loc['benign', df_APIs_IG.columns] = labels.loc[df_APIs_IG.columns, 'benign']
    else:
        df_DLLs_IG.loc['benign', df_DLLs_IG.columns] = labels.loc[df_DLLs_IG.columns, 'family']
        df_APIs_IG.loc['benign', df_APIs_IG.columns] = labels.loc[df_APIs_IG.columns, 'family']

    IG_DLLs = compute_information_gain(df_DLLs_IG)
    IG_APIs = compute_information_gain(df_APIs_IG)

    # Render in matplotlib
    # if plot:
    #     print("Saving DLLs IG for CCDF plot")
    #     filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'dlls_ig.pickle')
    #     IG_DLLs.to_pickle(filepath)
    #     print("Saving APIs IG for CCDF plot")
    #     filepath = os.path.join(config.PLOTS_DIRECTORY, experiment, 'apis_ig.pickle')
    #     IG_APIs.to_pickle(filepath)

    # igThresh = input("Which IG value do you want to cut DLLs?")
    # #Multiclass value
    # igThresh = 0.0152
    # #Binary value
    # igThresh = 0.0008
    # IG_DLLs  = IG_DLLs[IG_DLLs.IG>=float(igThresh)].index
    IG_DLLs = IG_DLLs.index

    filepath = os.path.join(config.SELECT_DIRECTORY, experiment, 'dlls.list')
    with open(filepath, 'w') as w_file:
        w_file.write("\n".join(IG_DLLs))

    # igThresh = input("Which IG value do you want to cut APIs?")
    # #Multiclass value
    # igThresh = 0.015
    # #Binary value
    # igThresh = 0.0006
    # IG_APIs  = IG_APIs[IG_APIs.IG>=float(igThresh)].index

    IG_APIs = IG_APIs.sort_values(by='IG', ascending=False)
    IG_APIs = IG_APIs.head(4500)
    IG_APIs = IG_APIs.index

    filepath = os.path.join(config.SELECT_DIRECTORY, experiment, 'apis.list')
    with open(filepath, 'w') as w_file:
        w_file.write("\n".join(IG_APIs))
