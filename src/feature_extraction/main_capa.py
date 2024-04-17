import argparse
import os

import pandas as pd

from src.dataset.malware_dataset import MalwareDataset
from dataset.builder.build_capa_dataset import build_capa_dataset


def setup_experiment_directories(experiment_path: str):
    d = os.path.join(experiment_path, "capa")
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

    build_capa_dataset(args.experiment, malware_dataset)
