from typing import List

from src.feature_extraction.static.top_features.top_feature_extractor import TopFeatureExtractor
from src.feature_extraction.static.top_features.top_imports import TopImports
from src.feature_extraction.static.top_features.top_ngrams import TopNGrams
from src.feature_extraction.static.top_features.top_opcodes import TopOpCodes
from src.feature_extraction.static.top_features.top_strings import TopStrings


class TopFeaturesExtractor:

    @staticmethod
    def extract_top_static_features(malware_dataset, experiment):
        # top_feature_extractors: List[TopFeatureExtractor] = [TopStrings(), TopImports(), TopNGrams(),
        #                                                      TopOpCodes()]
        top_feature_extractors: List[TopFeatureExtractor] = [TopNGrams()]
        
        for top_feature_extractor in top_feature_extractors:
            top_feature_extractor.top(malware_dataset, experiment)
