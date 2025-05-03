import subprocess
import os
from src.feature_extraction.static.static_feature_extractor import (
    StaticFeatureExtractor,
)
from src.feature_extraction import config


class CapaExtractor(StaticFeatureExtractor):
    def extract(self, sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
        cmd = f"./capa -j -v {filepath} > tmp/capa/{sha1}.json"
        result = subprocess.run(cmd, shell=True, text=True)
        print(result)
