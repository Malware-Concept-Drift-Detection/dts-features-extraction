import os
import pickle
import time
from functools import partial
from multiprocessing import Pool

import pandas as pd

from features_extraction.config.config import config
from features_extraction.static.generics import GenericExtractor
from features_extraction.static.headers import HeadersExtractor
from features_extraction.static.imports import ImportsExtractor
from features_extraction.static.ngrams import NGramsExtractor
from features_extraction.static.opcodes import OpCodesExtractor
from features_extraction.static.sections import SectionsExtractor
from features_extraction.static.strings import StringsExtractor
from p_tqdm import p_map

from features_extraction.utils import dump_data, load_data


def extract_features(
    sha1_family,
    n,
    generics_flag=False,
    headers_flag=False,
    all_sections=None,
    top_dlls=None,
    top_imports=None,
    top_strings=None,
    top_ngrams=None,
    top_opcodes=None,
):
    sha256, family = sha1_family
    filepath = os.path.join(config.malware_directory_path, family, sha256)
    # Row is a dictionary with sample hash and then all the features as key:value
    row = dict()
    row["sha256"] = sha256

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
        extracted_dlls, extracted_imports = ImportsExtractor().extract_and_pad(
            (filepath, top_dlls, top_imports)
        )
        row.update(extracted_dlls)
        row.update(extracted_imports)

    # Strings features
    if top_strings:
        extracted_strings = StringsExtractor().extract_and_pad((filepath, top_strings))
        row.update(extracted_strings)

    # N_grams features
    if top_ngrams:
        extracted_n_grams = NGramsExtractor().extract_and_pad((filepath, top_ngrams))
        row.update(extracted_n_grams)

    # Opcodes features
    if top_opcodes:
        extracted_opcodes = OpCodesExtractor().extract_and_pad(
            (filepath, top_opcodes, n)
        )
        row.update(extracted_opcodes)

    print(f"Done {sha256}", flush=True)
    return row


class DatasetBuilder:
    def build_dataset(self, n, experiment, malware_dataset):
        sha1s = malware_dataset.df_malware_family_fsd[["sha256", "family"]].to_numpy()
        top_features = self.__top_features_from_files(experiment)
        partial_extract_features = partial(
            extract_features,
            n=n,
            generics_flag=True,
            headers_flag=True,
            all_sections=top_features["all_sections"],
            top_strings=top_features["top_strings"],
            top_dlls=top_features["top_dlls"],
            top_imports=top_features["top_imports"],
            top_ngrams=top_features["top_n_grams"],
            top_opcodes=top_features["top_opcodes"],
        )

        t_start = time.time()
        results = p_map(partial_extract_features, sha1s, num_cpus=20)
        dataset = pd.DataFrame(results).set_index("sha256")
        dataset = self.__enrich_features(dataset)
        print(f"Total time: {(time.time() - t_start) / 60} min")
        print("Saving dataset to disk...")
        dump_data(
            os.path.join(
                experiment, config.final_dataset_directory, "dataset_final.pickle"
            ),
            dataset,
        )
        print("Done.")

    @staticmethod
    def __enrich_features(df):
        STD_SECTIONS = [
            ".text",
            ".data",
            ".rdata",
            ".idata",
            ".edata",
            ".rsrc",
            ".bss",
            ".crt",
            ".tls",
        ]
        to_drop = []
        for i_column in range(1, 17):
            column = f"pesection_{i_column}_name"
            column_exists = f"pesection_{i_column}_exists"
            column_is_standard = f"pesection_{i_column}_isStandard"
            df[column_exists] = df[column].map(lambda x: True if x != "none" else False)
            df[column_is_standard] = df[column].map(
                lambda x: True if x in STD_SECTIONS else False if x != "none" else False
            )
            to_drop.append(column)
        df = df.drop(to_drop, axis=1)
        return df

    @staticmethod
    def __top_features_from_files(experiment):
        top_features = {}
        top_feat_path = os.path.join(experiment, config.top_features_directory)
        print("Loading top features...")
        # Read all Section Features for padding
        with open(
            os.path.join(top_feat_path, "all_sections.list"), "r"
        ) as section_file:
            top_features.update(
                {
                    "all_sections": {
                        k: v
                        for k, v in (
                            l.split("\t") for l in section_file.read().splitlines()
                        )
                    }
                }
            )
        # Read most top DLLs
        top_features.update(
            {"top_dlls": load_data(os.path.join(top_feat_path, "top_dlls.pkl"))}
        )
        # Read most top Imports
        top_features.update(
            {"top_imports": load_data(os.path.join(top_feat_path, "top_apis.pkl"))}
        )
        # Read most top Strings
        top_features.update(
            {
                "top_strings": set(
                    load_data(os.path.join(top_feat_path, "top_strings.pkl"))
                )
            }
        )
        # Read most top N_grams
        top_features.update(
            {
                "top_n_grams": set(
                    load_data(os.path.join(top_feat_path, "top_byte_ngrams.pkl"))
                )
            }
        )
        # Read most top Opcodes
        top_features.update(
            {
                "top_opcodes": load_data(
                    os.path.join(top_feat_path, "top_opcode_ngrams.pkl")
                )
            }
        )
        print("Done.")
        return top_features
