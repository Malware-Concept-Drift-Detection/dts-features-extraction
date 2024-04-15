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
    vt_reports_path: str
    merge_dataset_path: str
    experiment_directory: str
    experiment_subdirectories: List[str]
    final_dataset_directory: str
    top_features_directory: str
    opcodes_max_size: int
    temp_results_dir: str
    results_directory: str
    n_processes: str


class ConfigFactory:

    @staticmethod
    def feature_extraction_configuration() -> FeatureExtractionConfig:
        """
        Creates an EnvironmentConfig object by extracting information from the config file,
        whose path is specified by GLOBAL_CONFIG_PATH environment variable.
        :return: environment config
        """

        return FeatureExtractionConfig(
            malware_directory_path=os.environ.get("MALWARE_DIR_PATH"),
            vt_reports_path=os.environ.get("VT_REPORTS_PATH"),
            merge_dataset_path=os.environ.get("MERGE_DATASET_PATH"),
            experiment_directory="experiment",
            experiment_subdirectories=['dataset', 'top_features', 'results'],
            final_dataset_directory=os.environ.get("FINAL_DATASET_DIR"),
            top_features_directory="top_features",
            opcodes_max_size=3,
            temp_results_dir=".temp",
            results_directory="results",
            n_processes=os.environ.get("N_PROCESSES")
        )


# Singleton
config = ConfigFactory().feature_extraction_configuration()
