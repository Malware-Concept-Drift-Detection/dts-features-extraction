import os
from collections import Counter
from functools import partial
from itertools import islice

import pandas as pd
from info_gain import info_gain
from p_tqdm import p_map

from features_extraction.static.top_features.top_feature_extractor import (
    TopFeatureExtractor,
)
from features_extraction.config.config import config
from features_extraction.static.imports import ImportsExtractor
from features_extraction.utils import dump_data


class TopImports(TopFeatureExtractor):
    def top(self, malware_dataset, experiment):
        sha1s = malware_dataset.training_dataset[["sha256", "family"]].to_numpy()
        samples_len = len(sha1s)
        imports_extractor = ImportsExtractor()
        print(
            f"Extracting imports (DLL and APIs) from all the {samples_len} samples in the training set"
        )
        all_samples_imports = p_map(
            imports_extractor.extract, sha1s, num_cpus=config.n_processes
        )
        all_samples_imports = {k: v for d in all_samples_imports for k, v in d.items()}

        # Computing frequency
        print("Computing DLLs and APIs prevalence")
        top_dlls = Counter()
        top_apis = Counter()
        for sha1, content in all_samples_imports.items():
            top_dlls.update(content["dlls"])
            top_apis.update(content["imps"])
        print(f"Total number of unique DLLs is: {len(top_dlls.keys())}")
        print(f"Total number of unique APIs is: {len(top_apis.keys())}")

        # Filtering the most and least common
        print("Filtering the most and least common")
        upper_bound = int(
            len(all_samples_imports) - len(all_samples_imports) * 0.1 / 100
        )
        lower_bound = int(len(all_samples_imports) * 0.1 / 100)
        top_dlls = set(
            [k for k, v in top_dlls.items() if lower_bound < v < upper_bound]
        )
        top_apis = set(
            [k for k, v in top_apis.items() if lower_bound < v < upper_bound]
        )

        dump_data(
            os.path.join(experiment, config.top_features_directory, "top_dlls.pkl"),
            top_dlls,
        )
        dump_data(
            os.path.join(experiment, config.top_features_directory, "top_apis.pkl"),
            top_apis,
        )

        # print("Computing Information Gain")
        # partial_df_ig = partial(self.__df_ig, top_dlls=top_dlls, top_apis=top_apis)
        # chunks = [chunk for chunk in self.__create_chunks(all_samples_imports, 500)]
        # results = p_map(partial_df_ig, chunks)

        # df_dlls_ig = []
        # df_apis_ig = []
        # for partial_df_dlls_ig, partial_df_apis_ig in results:
        #     df_dlls_ig.append(partial_df_dlls_ig)
        #     df_apis_ig.append(partial_df_apis_ig)

        # df_dlls_ig = pd.concat(df_dlls_ig, axis=1)
        # df_apis_ig = pd.concat(df_apis_ig, axis=1)

        # df = malware_dataset.training_dataset
        # df_dlls_ig.loc["family", df_dlls_ig.columns] = df[
        #     df["sha256"].isin(list(df_dlls_ig.columns))
        # ]["family"]
        # df_apis_ig.loc["family", df_apis_ig.columns] = df[
        #     df["sha256"].isin(list(df_apis_ig.columns))
        # ]["family"]

        # ig_dlls = self.__compute_information_gain(df_dlls_ig)
        # ig_apis = self.__compute_information_gain(df_apis_ig)
        # ig_dlls = ig_dlls.index

        # filepath = os.path.join(experiment, config.top_features_directory, "dlls.list")
        # with open(filepath, "w") as w_file:
        #     w_file.write("\n".join(ig_dlls))

        # ig_apis = ig_apis.sort_values(by="IG", ascending=False)
        # ig_apis = ig_apis.head(4500)
        # ig_apis = ig_apis.index

        # filepath = os.path.join(experiment, config.top_features_directory, "apis.list")
        # with open(filepath, "w") as w_file:
        #     w_file.write("\n".join(ig_apis))

    @staticmethod
    def __compute_information_gain(imports):
        labels = imports.loc["family"]
        imports = imports.drop("family")
        ret_dict = pd.DataFrame(0.0, index=imports.index, columns=["IG"])
        for imp, row in imports.iterrows():
            ret_dict.at[imp, "IG"] = info_gain.info_gain(labels, row)
        return ret_dict

    @staticmethod
    def __create_chunks(data, size=500):
        it = iter(data)
        for i in range(0, len(data), size):
            yield {k: data[k] for k in islice(it, size)}

    @staticmethod
    def __df_ig(sha1s, top_dlls, top_apis):
        df_dlls_ig = pd.DataFrame(True, index=list(top_dlls), columns=sha1s)
        df_api_ig = pd.DataFrame(True, index=list(top_apis), columns=sha1s)

        for sha1, dictionary in sha1s.items():
            # Merge top dlls and apis
            considered_dlls = set(sha1s[sha1]["dlls"]) & top_dlls
            considered_apis = set(sha1s[sha1]["imps"]) & top_apis
            # Mark top dlls and apis
            extracted_dlls = pd.Series(False, index=top_dlls)
            extracted_apis = pd.Series(False, index=top_apis)
            for considered_DLL in considered_dlls:
                extracted_dlls[considered_DLL] = True
            df_dlls_ig[sha1] = extracted_dlls

            for considered_api in considered_apis:
                extracted_apis[considered_api] = True
            df_api_ig[sha1] = extracted_apis
        return df_dlls_ig, df_api_ig
