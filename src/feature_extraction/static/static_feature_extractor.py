class StaticFeatureExtractor:
    def extract(self, args):
        """
        Base extract method, to be overridden by subclasses
        """
        raise NotImplementedError("Subclasses must implement this method")

    def extract_and_pad(self, args):
        """
        Base extract and pad method, to be overridden by subclasses
        """
        raise NotImplementedError("Subclasses must implement this method")
