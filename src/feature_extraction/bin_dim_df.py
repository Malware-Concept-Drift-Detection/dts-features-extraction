import os
import pandas as pd

from src.feature_extraction import config
from src.dataset.malware_dataset import MalwareDataset
from multiprocessing import Pool


def get_bin_dim(args):
    sha, family = args
    return os.path.getsize(os.path.join(config.MALWARE_DIRECTORY, family, sha))

malware_dataset = MalwareDataset(pd.Timestamp("2021-09-03 13:47:49"))

sha_fam_df = malware_dataset.df_malware_family_fsd
sha_fam = sha_fam_df[['sha256', 'family']].to_numpy()

with Pool(config.CORES) as p:
    binaries_dim = p.map(get_bin_dim, sha_fam)

sha_fam_df["dim"] = binaries_dim

sha_fam_df = sha_fam_df.sort_values(by='dim', ascending=False)
print(sha_fam_df.head())

sha_fam_df.to_csv('bin_dim.csv', index=False)