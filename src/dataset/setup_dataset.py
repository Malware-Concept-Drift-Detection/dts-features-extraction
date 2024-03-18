import os

import pandas as pd
from io import StringIO

from tqdm import tqdm


class MalwareDatasetBuilder:

    def __init__(self):
        self.__base_dir = os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def __build_sha_fsd_df(sha_fsd_file_path: str) -> pd.DataFrame:
        """
        Open VT reports and get SHA256 and first_submission_date values for each json (line).
        """
        malwares_first_sub_date = []
        with open(sha_fsd_file_path, 'r') as reports:
            sha256_key, first_sub_date_key = 'sha256', 'first_submission_date'
            # Iterate through all reports
            for report in reports:
                df_report = pd.read_json(StringIO(report))['data']['attributes']
                sha256, first_sub_date = df_report[sha256_key], df_report[first_sub_date_key]
                malwares_first_sub_date.append((sha256, first_sub_date))
        return pd.DataFrame(malwares_first_sub_date, columns=[sha256_key, first_sub_date_key])

    @staticmethod
    def __build_sha_family_df(malware_dir_path: str, min_samples: int = 100) -> pd.DataFrame:
        """
        Build dataset with malware's id (SHA256) and relative family columns
        """
        families = os.listdir(malware_dir_path)
        datasets = []
        for family in tqdm(families):
            current_samples = os.listdir(os.path.join(malware_dir_path, family))
            if len(current_samples) >= min_samples:
                family_dataset = pd.DataFrame({"sha256": current_samples, "family": family})
                datasets.append(family_dataset)
        df = pd.concat(datasets, ignore_index=True)
        # filepath = os.path.join(experiment_path, DATASET_DIRECTORY, 'sha256_family.csv')
        # df.to_csv(filepath)
        return df

    def malware_family_fsd_df(self, sha_fsd_file_path: str = None,
                              malware_dir_path: str = None,
                              min_samples: int = 100) -> pd.DataFrame:

        sha_fsd_file_path = "/home/luca/Desktop/WD/NortonDataset670/dataset_info/vt_reports67k.jsons" \
            if sha_fsd_file_path is None else sha_fsd_file_path
        malware_dir_path = "/home/luca/Desktop/WD/NortonDataset670/MALWARE/" \
            if malware_dir_path is None else malware_dir_path
        merge_dataset_filename = f"{self.__base_dir}/../vt_reports/merge.csv"

        if os.path.exists(merge_dataset_filename):
            return pd.read_csv(merge_dataset_filename, parse_dates=["first_submission_date"])
        else:
            df = pd.merge(left=self.__build_sha_family_df(malware_dir_path, min_samples),
                          right=self.__build_sha_fsd_df(sha_fsd_file_path), on="sha256")
            # df.set_index("sha256", inplace=True)
            df["benign"] = False
            df["first_submission_date"] = (df["first_submission_date"]
                                           .apply(lambda t: pd.to_datetime(t, unit="s")))
            print(df.columns)
            df.to_csv(merge_dataset_filename, index=False)
            return df


class MalwareDataset:

    def __init__(self, split: pd.Timestamp):
        fsd = "first_submission_date"
        self.df_malware_family_fsd = MalwareDatasetBuilder().malware_family_fsd_df()
        self.training_dataset = self.df_malware_family_fsd[self.df_malware_family_fsd[fsd] < split]
        self.testing_dataset = self.df_malware_family_fsd[self.df_malware_family_fsd[fsd] >= split]


def extract_malware_family(file_path) -> pd.DataFrame:
    df = pd.read_csv(file_path, usecols=['SHA256', 'FAMILY'])
    return df.rename(str.lower, axis='columns')


malware_dataset = MalwareDataset(pd.Timestamp("2021-01-01"))

# df1 = extract_malware_family(
#     "/home/luca/Desktop/WD/NortonDataset670/dataset_info/siggregator_all_samples_no_fuzzy_hash.csv")
#
# print(set(malware_dataset.df_malware_family_fsd["family"].unique()) == set(df1["family"].unique()))

# if __name__ == "__main__":
#     # Get datasets path
#     base_dir = os.path.dirname(os.path.abspath(__file__))
#     parser = argparse.ArgumentParser(description='Build Malware dataset '
#                                                  '[SHA256, family, first_submission_date]')
#     parser.add_argument("--vt_reports_path", required=False,
#                         default=)
#     parser.add_argument("--malware_dir_path", required=False,
#                         default=)
#     parser.add_argument("--merge_path", required=False,
#                         default=f"{base_dir}/../../vt_reports/merge.csv")
#     args, _ = parser.parse_known_args()
#
#     df = malware_family_fsd_df(sha_fsd_file_path=args.vt_reports_path,
#                                malware_dir_path=args.malware_dir_path)
#     df.to_csv(args.merge_path, index=False)
