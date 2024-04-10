from typing import List
from src.feature_extraction.static.static_feature_extractor import StaticFeatureExtractor
from src.feature_extraction.top_features.top_imports import TopImports
from src.feature_extraction.top_features.top_ngrams import TopNGrams
from src.feature_extraction.top_features.top_opcodes import TopOpCodes
from src.feature_extraction.top_features.top_strings import TopStrings


class TopFeaturesExtractor:

    @staticmethod
    def extract_top_static_features(malware_dataset, experiment):
        top_feature_extractors: List[StaticFeatureExtractor] = [TopStrings(), TopImports(), TopNGrams(), 
                                                                TopOpCodes()]
        for top_feature_extractor in top_feature_extractors:
            top_feature_extractor.top(malware_dataset, experiment)
