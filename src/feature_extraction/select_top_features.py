from src.feature_extraction.PRE_topFeatures import top_ngrams
from src.feature_extraction.PRE_topFeatures import top_opcodes
from src.feature_extraction.PRE_topFeatures import top_strings
from src.feature_extraction.PRE_topFeatures import top_imports


def compute_top_features(plot, binary, experiment):
    top_imports.top_imports(plot, binary, experiment)
    top_strings.top_strings(plot, binary, experiment)
    top_ngrams.top_n_grams(plot, binary, experiment)
    top_opcodes.top_opcodes(plot, binary, experiment)
    n = top_opcodes.post_selection_op_codes(binary, experiment)
    return n
