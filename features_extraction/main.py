import argparse
import os

import pandas as pd

from features_extraction.static.top_features.top_features_extractor import (
    TopFeaturesExtractor,
)
from features_extraction.config.config import config
from features_extraction.malware_dataset.malware_dataset import MalwareDataset
from features_extraction.static.extract_features_from_top import DatasetBuilder


def setup_experiment_directories(experiment_path: str):
    for parent in config.experiment_subdirectories:
        d = os.path.join(experiment_path, parent)
        if not os.path.exists(d):
            os.makedirs(d)


if __name__ == "__main__":
    # Get arguments
    parser = argparse.ArgumentParser(
        description="Pipeline for building malware features dataset"
    )
    parser.add_argument("--experiment", required=True)

    args, _ = parser.parse_known_args()
    setup_experiment_directories(args.experiment)

    # First step: build [sha256, first submission date, family] dataset,
    # choosing 62%-38% as training-test split
    print("Building dataset with malware families and submission dates")
    malware_dataset = MalwareDataset()

    # Second step: select top features for imports, ngrams, opcodes and strings
    # -> side effect on the file system inside experiment path
    print("Extracting top features...")
    TopFeaturesExtractor(experiment_path=args.experiment).extract_top_static_features(
        malware_dataset
    )

    # Third step: Build dataset -> side effect on the file system inside experiment path
    # dataset directory
    print("Building dataset...")
    DatasetBuilder().build_dataset(
        len(malware_dataset.df_malware_family_fsd), args.experiment, malware_dataset
    )
