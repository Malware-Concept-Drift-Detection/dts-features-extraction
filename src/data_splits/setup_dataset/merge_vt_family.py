import argparse
import os

import pandas as pd
from io import StringIO

from tqdm import tqdm


def build_sha_fsd_df(sha_fsd_file_path: str) -> pd.DataFrame:
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


def build_sha_family_df(malware_dir_path: str, min_samples: int = 100) -> pd.DataFrame:
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


def build_malware_family_fsd_df(sha_fsd_file_path: str, malware_dir_path: str,
                                min_samples: int = 100) -> pd.DataFrame:
    return pd.merge(left=build_sha_family_df(malware_dir_path, min_samples),
                    right=build_sha_fsd_df(sha_fsd_file_path), on="sha256")


if __name__ == "__main__":
    # Get datasets path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description='Build Malware dataset '
                                                 '[SHA256, family, first_submission_date]')
    parser.add_argument("--vt_reports_path", required=False,
                        default=f"{base_dir}/../../vt_reports/vt_reports67k.jsons")
    parser.add_argument("--malware_dir_path", required=False,
                        default="/run/media/luca/WD/NortonDataset670/MALWARE/")
    parser.add_argument("--merge_path", required=False,
                        default=f"{base_dir}/../../vt_reports/merge.csv")
    args, _ = parser.parse_known_args()

    df = build_malware_family_fsd_df(sha_fsd_file_path=args.vt_reports_path,
                                     malware_dir_path=args.malware_dir_path)
    df.to_csv(args.merge_path, index=False)
