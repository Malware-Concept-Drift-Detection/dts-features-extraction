
import pickle
import pandas as pd


with open("/home/luca/ml-malware-concept-drift/tmp/dataset/dataset.pickle", "rb") as f:
    df = pickle.load(f)

print(df.shape)

print(len(set(list(df.index))))