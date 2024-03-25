import argparse
import os
import time

import pandas as pd

from src.feature_extraction import config
from src.dataset.malware_dataset import MalwareDataset
from src.feature_extraction.build_dataset import build_dataset
from src.feature_extraction.compute_top_features import compute_top_features


def setup_experiment_directories(experiment_path: str):
    for parent in config.PARENTS:
        d = os.path.join(experiment_path, parent)
        if not os.path.exists(d):
            os.makedirs(d)


if __name__ == '__main__':
    # Get arguments
    parser = argparse.ArgumentParser(description='Pipeline for binary or family classification')
    parser.add_argument("--experiment", required=True)

    args, _ = parser.parse_known_args()
    setup_experiment_directories(args.experiment)

    # First step: build [sha256, first submission date, family] dataset,
    # choosing 62%-38% as training-test split
    malware_dataset = MalwareDataset(pd.Timestamp("2021-09-03 13:47:49"))

    # Second step: select top features for imports, ngrams, opcodes and strings
    n = compute_top_features(malware_dataset, args.experiment)
    # Third step: Build dataset
    build_dataset(n, args.experiment, malware_dataset)
