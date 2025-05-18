from typing import List

from features_extraction.static.top_features.top_feature_extractor import (
    TopFeatureExtractor,
)
from features_extraction.static.top_features.top_imports import TopImports
from features_extraction.static.top_features.top_ngrams import TopNGrams
from features_extraction.static.top_features.top_opcodes import TopOpCodes
from features_extraction.static.top_features.top_strings import TopStrings


class TopFeaturesExtractor:
    @staticmethod
    def extract_top_static_features(malware_dataset, experiment):
        top_feature_extractors: List[TopFeatureExtractor] = [
            TopStrings(),
            TopImports(),
            TopNGrams(),
            TopOpCodes(),
        ]
        for top_feature_extractor in top_feature_extractors:
            top_feature_extractor.top(malware_dataset, experiment)
