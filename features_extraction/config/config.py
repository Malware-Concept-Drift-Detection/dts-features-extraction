import os
from dataclasses import dataclass
import random
from typing import List

random.seed(42)


@dataclass(frozen=True)
class FeatureExtractionConfig:
    """
    Sum type modelling feature extraction configuration.
    """

    malware_directory_path: str
    # vt_reports_path: str
    splitted_dataset_path: str
    # merge_dataset_path: str
    experiment_directory: str
    experiment_subdirectories: List[str]
    final_dataset_directory: str
    top_features_directory: str
    opcodes_max_size: int
    temp_results_dir: str
    results_directory: str
    n_processes: int
    random_seed: int


class ConfigFactory:
    @staticmethod
    def standard_feature_extraction_config() -> FeatureExtractionConfig:
        """
        Return a standard FeatureExtractionConfig
        :return: FeatureExtractionConfig
        """
        return FeatureExtractionConfig(
            malware_directory_path="/home/luca/WD/NortonDataset670/MALWARE/",
            vt_reports_path="/home/luca/WD/NortonDataset670/dataset_info/vt_reports67k.jsons",
            merge_dataset_path=f"{os.path.dirname(os.path.abspath(__file__))}/../../vt_reports/merge.csv",
            experiment_directory="experiment",
            experiment_subdirectories=["dataset", "top_features", "results"],
            final_dataset_directory="dataset",
            top_features_directory="top_features",
            opcodes_max_size=3,
            temp_results_dir=".temp",
            results_directory="results",
            n_processes=32,
            random_seed=42,
        )

    @staticmethod
    def feature_extraction_config() -> FeatureExtractionConfig:
        """
        Creates an FeatureExtractionConfig object by extracting information from the env vars,
        :return: FeatureExtractionConfig
        """

        return FeatureExtractionConfig(
            malware_directory_path=os.environ.get("MALWARE_DIR_PATH"),
            splitted_dataset_path=os.environ.get("SPLITTED_DATASET_PATH"),
            # vt_reports_path=os.environ.get("VT_REPORTS_PATH"),
            # merge_dataset_path=os.environ.get("MERGE_DATASET_PATH"),
            experiment_directory="experiment",
            experiment_subdirectories=["dataset", "top_features", "results"],
            final_dataset_directory=os.environ.get("FINAL_DATASET_DIR"),
            top_features_directory="top_features",
            opcodes_max_size=3,
            temp_results_dir=".temp",
            results_directory="results",
            n_processes=int(os.environ.get("N_PROCESSES")),
            random_seed=42,
        )


# Singleton
config = ConfigFactory().feature_extraction_config()
