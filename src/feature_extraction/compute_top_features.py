from src.feature_extraction.top_features import top_ngrams
from src.feature_extraction.top_features import top_opcodes
from src.feature_extraction.top_features import top_strings
from src.feature_extraction.top_features import top_imports


def compute_top_features(malware_dataset, experiment):
    #top_imports.top_imports(malware_dataset, experiment)
    top_strings.top_strings(malware_dataset, experiment)
    # top_ngrams.top_n_grams(malware_dataset, experiment)
    # top_opcodes.top_opcodes(malware_dataset, experiment)
    # n = top_opcodes.post_selection_op_codes(malware_dataset, experiment)
    return 0
