class TopFeatureExtractor:
    def top(self, malware_dataset, experiment):
        """
        Base top method, to be overridden by subclasses
        """
        raise NotImplementedError("Subclasses must implement this method")

    def post_feature_selection(self, malware_dataset, experiment):
        pass
