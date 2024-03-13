import argparse
import os
import shutil
import time

from src.feature_extraction import config
from src.feature_extraction.compute_top_features import compute_top_features
from src.feature_extraction.build_dataset import build_dataset

if __name__ == '__main__':
    # Get arguments
    parser = argparse.ArgumentParser(description='Pipeline for binary or family classification')
    parser.add_argument("--experiment", required=True)
    # parser.add_argument("--minSamples", required=True)
    # To Remove an experiment
    parser.add_argument("--remove", action="store_true")
    args, _ = parser.parse_known_args()

    # Check if the intended action is to remove an experiment
    if args.remove:
        for parent in config.PARENTS:
            d = os.path.join(parent, args.experiment)
            if os.path.exists(d):
                shutil.rmtree(d)
        exit()

    # Get time
    start = time.time()  # those are seconds

    # Setup directories
    for parent in config.PARENTS:
        d = os.path.join(parent, args.experiment)
        if not os.path.exists(d):
            os.makedirs(d)

    # First step: build dataframe with all the labels, families and paths
    # config.buildLabelDataFrame(args.experiment,int(args.minSamples),args.excludepacked,args.binary)

    suffixes = ['']

    for suffix in suffixes:
        # Second step: select top features for imports, ngrams, opcodes and strings
        n = compute_top_features(False, args.experiment + suffix)
        # Third step: Build dataset
        build_dataset(False, n, args.experiment + suffix)

    # Fourth step: Classifier
    # classifier.tuneTrees(args.binary,args.experiment)
    # classifier.tuneDepth(args.binary,args.experiment)

    # Fifth step: Classifier
    # if args.binary:
    #     # binaryclass.classify(args.experiment,args.plot)
    #     # XGBoostBinaryclass.classify(args.experiment,args.plot)
    #     binary_classification.aggregate_results(args.experiment)
    # else:
    #     family_classification.classify(args.experiment, args.plot)
    #     # XGBoostMulticlass.classify(args.experiment,args.plot)
    #     family_classification.aggregate_results(args.experiment)

    # Sixt step: One vs Rest classifier
    # oneVsRest.classify(args.binary,args.experiment)

    # Pipeline complete
    end = time.time()  # those are seconds
    elapsed = int(end - start)
    print("It took {} minutes to run the pipeline".format(elapsed / 60))
