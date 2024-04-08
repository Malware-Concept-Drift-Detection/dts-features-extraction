
from src.feature_extraction.static.capa import CapaExtractor
from multiprocessing import Pool
from src.feature_extraction import config


def build_capa_dataset(experiment, malware_dataset):

    # For singleton
    sha1s = malware_dataset.df_malware_family_fsd[['sha256', 'family']].to_numpy()

    capa_extractor = CapaExtractor()

    with Pool(config.CORES) as p:
        p.map(capa_extractor.extract, sha1s)