from src.feature_extraction.top_features import top_ngrams
from src.feature_extraction.top_features import top_opcodes
from src.feature_extraction.top_features import top_strings
from src.feature_extraction.top_features import top_imports


def compute_top_features(experiment):
    #top_imports.top_imports(experiment)
    top_strings.top_strings(experiment)
    # top_ngrams.top_n_grams(binary, experiment)
    # top_opcodes.top_opcodes(binary, experiment)
    # n = top_opcodes.post_selection_op_codes(binary, experiment)
    return 1
