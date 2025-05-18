import os
import random

random.seed(42)

# VirusTotal reports path
VT_REPORTS = "/home/luca/WD/NortonDataset670/dataset_info/vt_reports67k.jsons"

# Merge Dataset path
MERGE_DATASET_PATH = (
    f"{os.path.dirname(os.path.abspath(__file__))}/../vt_reports/merge.csv"
)

# Malware directory
MALWARE_DIRECTORY = "/home/luca/WD/NortonDataset670/MALWARE/"

# Parents directories
PARENTS = ["dataset", "top_features", "results"]

# Dataset directory
DATASET_DIRECTORY = "dataset"

# Directory of frequency pickles
TOP_FEATURES_SUBDIR = "top_features"

# Max size for opcode Ngrams
OPCODES_MAX_SIZE = 3

# Save temp files
TEMP_DIRECTORY = ".temp"

# Save results
RESULT_DIRECTORY = "results"

# How many cores do you have
CORES = 32

# Feature identification
FEAT_PREFIX = {
    "generic_": "generic",
    "pesection": "sections",
    "header_": "header",
    "str_": "strings",
    "imp_": "imports",
    "ngram_": "ngrams",
    "opcode_": "opcodes",
    "dynamic_file": "dynamic_file",
    "dynamic_mutex": "dynamic_mutex",
    "dynamic_network": "dynamic_network",
    "dynamic_process": "dynamic_process",
    "dynamic_registry": "dynamic_registry",
    "dynamic_service": "dynamic_service",
    "dynamic_thread": "dynamic_thread",
}

FEAT_SUFFIX = {"dll": "dlls"}

FEAT_ALL = FEAT_PREFIX.copy()
FEAT_ALL["dll"] = "dlls"
