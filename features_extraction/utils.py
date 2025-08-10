import pickle


def load_data(path):
    with open(path, "rb") as f:
        data = pickle.load(f)
    return data


def dump_data(path, data):
    with open(path, "wb") as f:
        pickle.dump(data, f)
