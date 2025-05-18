class TopFeatureExtractor:
    def top(self, malware_dataset, experiment):
        """
        Base top method, to be overridden by subclasses
        """
        raise NotImplementedError("Subclasses must implement this method")
