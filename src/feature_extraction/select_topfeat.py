from PRE_topFeatures import top_ngrams
from PRE_topFeatures import top_opcodes
from PRE_topFeatures import top_strings


def computeTopFeatures(plot, binary, experiment):
    # top_imports.top_imports(plot,binary,experiment)
    top_strings.top_strings(plot, binary, experiment)
    top_ngrams.top_nGrams(plot, binary, experiment)
    top_opcodes.top_opCodes(plot, binary, experiment)
    N = top_opcodes.postSelection_opCodes(binary, experiment)
    return N
