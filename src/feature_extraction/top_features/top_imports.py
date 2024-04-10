import os
from collections import Counter
from functools import partial
from itertools import islice

import pandas as pd
from info_gain import info_gain
from p_tqdm import p_map

from src.feature_extraction.top_features.top_feature_extractor import TopFeatureExtractor
from src.feature_extraction import config
from src.feature_extraction.static.imports import ImportsExtractor


class TopImports(TopFeatureExtractor):

    def top(self, malware_dataset, experiment):

        sha1s = malware_dataset.training_dataset[['sha256', 'family']].to_numpy()
        samples_len = len(sha1s)
        imports_extractor = ImportsExtractor()
        print(f"Extracting imports (DLL and APIs) from all the {samples_len} samples in the training set")
        all_samples_imports = p_map(imports_extractor.extract, sha1s, num_cpus=config.CORES)
        all_samples_imports = {k: v for d in all_samples_imports for k, v in d.items()}

        # Checking problems with extraction
        # problematic_sha1s = {k: v for k, v in all_samples_imports.items() if v['error']}
        # utils.update_label_data_frame(experiment, problematic_sha1s)
        # all_samples_imports = {k: v for k, v in all_samples_imports.items() if not v['error']}

        # Computing frequency
        print("Computing DLLs and APIs prevalence")
        top_dlls = Counter()
        top_apis = Counter()
        for sha1, content in all_samples_imports.items():
            top_dlls.update(content['dlls'])
            top_apis.update(content['imps'])
        print(f"Total number of unique DLLs is: {len(top_dlls.keys())}")
        print(f"Total number of unique APIs is: {len(top_apis.keys())}")

        # Filtering the most and least common
        print("Filtering the most and least common")
        upper_bound = int(len(all_samples_imports) - len(all_samples_imports) * .1 / 100)
        lower_bound = int(len(all_samples_imports) * .1 / 100)
        top_dlls = set([k for k, v in top_dlls.items() if lower_bound < v < upper_bound])
        top_apis = set([k for k, v in top_apis.items() if lower_bound < v < upper_bound])

        print("Computing Information Gain")
        partial_df_ig = partial(self.__df_ig, top_dlls=top_dlls, top_apis=top_apis)
        chunks = [chunk for chunk in self.__create_chunks(all_samples_imports, 500)]
        results = p_map(partial_df_ig, chunks)

        df_dlls_ig = []
        df_apis_ig = []
        for partial_df_dlls_ig, partial_df_apis_ig in results:
            df_dlls_ig.append(partial_df_dlls_ig)
            df_apis_ig.append(partial_df_apis_ig)

        df_dlls_ig = pd.concat(df_dlls_ig, axis=1)
        df_apis_ig = pd.concat(df_apis_ig, axis=1)

        df = malware_dataset.df_malware_family_fsd
        df_dlls_ig.loc['benign', df_dlls_ig.columns] = df[df["sha256"].isin(list(df_dlls_ig.columns))]["family"]
        df_apis_ig.loc['benign', df_apis_ig.columns] = df[df["sha256"].isin(list(df_apis_ig.columns))]["family"]

        # print(df_dlls_ig.head())
        # print(df_apis_ig.head())

        ig_dlls = self.__compute_information_gain(df_dlls_ig)
        ig_apis = self.__compute_information_gain(df_apis_ig)

        # igThresh = input("Which IG value do you want to cut DLLs?")
        # #Multiclass value
        # igThresh = 0.0152
        # #Binary value
        # igThresh = 0.0008
        # ig_dlls  = ig_dlls[ig_dlls.IG>=float(igThresh)].index
        ig_dlls = ig_dlls.index

        filepath = os.path.join(experiment, config.TOP_FEATURES_SUBDIR, 'dlls.list')
        with open(filepath, 'w') as w_file:
            w_file.write("\n".join(ig_dlls))

        # igThresh = input("Which IG value do you want to cut APIs?")
        # #Multiclass value
        # igThresh = 0.015
        # #Binary value
        # igThresh = 0.0006
        # ig_apis  = ig_apis[ig_apis.IG>=float(igThresh)].index

        ig_apis = ig_apis.sort_values(by='IG', ascending=False)
        ig_apis = ig_apis.head(4500)
        ig_apis = ig_apis.index

        filepath = os.path.join(experiment, config.TOP_FEATURES_SUBDIR, 'apis.list')
        with open(filepath, 'w') as w_file:
            w_file.write("\n".join(ig_apis))

    @staticmethod
    def __compute_information_gain(imports):
        labels = imports.loc['benign']
        imports = imports.drop('benign')
        ret_dict = pd.DataFrame(0.0, index=imports.index, columns=['IG'])
        for imp, row in imports.iterrows():
            ret_dict.at[imp, 'IG'] = info_gain.info_gain(labels, row)
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
            considered_dlls = set(sha1s[sha1]['dlls']) & top_dlls
            considered_apis = set(sha1s[sha1]['imps']) & top_apis
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
