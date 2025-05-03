from tqdm import tqdm
from p_tqdm import p_map
from src.feature_extraction import config
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from collections import Counter
from sklearn import model_selection
import pickle
import random
import seaborn as sns
import matplotlib.pyplot as plt
from functools import partial, reduce
from itertools import product as xprod
from scipy.stats import entropy
from datetime import datetime


def pad_confusion_matrix(cm):
    # Check that all the columns are there
    shape = cm.shape
    if shape[0] != shape[1]:
        rows = set(cm.index)
        cols = set(cm.columns)
        missing = rows - cols
        for m in missing:
            cm[m] = 0
        cm = cm[cm.index]
    return cm


def train_and_save(experiment, name, X, y):
    path = os.path.join(config.RESULT_DIRECTORY, experiment, name)
    try:
        os.makedirs(path)
    except:
        pass
    # Check if this was run:
    skip = False
    for file in os.listdir(path):
        d = datetime.fromtimestamp(os.path.getmtime(os.path.join(path, file)))
        if d.day > 21 and d.month == 8:
            skip = True
        else:
            skip = False
            break
    if skip:
        return
    clf = RandomForestClassifier(
        n_jobs=72, max_depth=None, n_estimators=225, max_features="sqrt"
    )

    classification_result = []
    probability_result = []
    confusion_matrix = []
    feature_importance = []
    classification_reports = []
    clfs = []

    n_splits = 5
    kfold = model_selection.StratifiedShuffleSplit(n_splits=n_splits, test_size=0.2)
    for train_index, test_index in kfold.split(X, y):
        # Compute and Save each round
        X_train = X.iloc[train_index]
        X_test = X.iloc[test_index]
        y_train = y.iloc[train_index]
        y_test = y.iloc[test_index]
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_proba = clf.predict_proba(X_test)
        if name == "ft_1-ff_0-st_1-sf_0":
            clfs.append(clf)

        # Prediction Probability
        current_probability = pd.DataFrame(y_test)
        current_probability.loc[:, clf.classes_] = y_proba
        current_probability["Entropy"] = current_probability[clf.classes_].apply(
            entropy, axis=1
        )
        probability_result.append(current_probability)

        # Prediction result
        current_result = pd.DataFrame(y_test)
        current_result.index.names = ["sample_hash"]
        current_result["PredictedLabel"] = y_pred
        current_result = current_result.rename(columns={"family": "TrueLabel"})
        classification_result.append(current_result)

        # Confusion Matrix
        current_cm = pd.crosstab(
            y_test,
            y_pred,
            rownames=["True Value"],
            colnames=["Predicted Value"],
            normalize="index",
        )
        current_cm = pad_confusion_matrix(current_cm)
        confusion_matrix.append(current_cm)

        # Feature Importance
        current_importance = pd.DataFrame(
            clf.feature_importances_, index=X_train.columns, columns=["feat_importance"]
        ).sort_values(by="feat_importance", ascending=False)
        feature_importance.append(current_importance)

        # Classification parameters
        current_report = pd.DataFrame(
            classification_report(y_test, y_pred, output_dict=True)
        )
        current_report = current_report.swapaxes("index", "columns")
        current_report = current_report.drop(["accuracy", "macro avg", "weighted avg"])
        current_report = current_report.drop(["support"], axis=1)
        current_report["accuracy"] = 0.00
        for family in current_report.index:
            current_report.at[family, "accuracy"] = current_cm.at[family, family]
        current_report.index.names = ["name"]
        classification_reports.append(current_report)

    # Save results
    if name == "ft_1-ff_0-st_1-sf_0":
        with open(
            os.path.join(
                config.RESULT_DIRECTORY, experiment, name, "classifiers.pickle"
            ),
            "wb",
        ) as w_file:
            pickle.dump(clfs, w_file)
    with open(
        os.path.join(
            config.RESULT_DIRECTORY,
            experiment,
            name,
            "trueLabel_probability_list.pickle",
        ),
        "wb",
    ) as w_file:
        pickle.dump(probability_result, w_file)
    with open(
        os.path.join(
            config.RESULT_DIRECTORY,
            experiment,
            name,
            "trueLabel_predictedLabel_list.pickle",
        ),
        "wb",
    ) as w_file:
        pickle.dump(classification_result, w_file)
    with open(
        os.path.join(
            config.RESULT_DIRECTORY, experiment, name, "confusionMatrix_list.pickle"
        ),
        "wb",
    ) as w_file:
        pickle.dump(confusion_matrix, w_file)
    with open(
        os.path.join(
            config.RESULT_DIRECTORY, experiment, name, "featureImportance_list.pickle"
        ),
        "wb",
    ) as w_file:
        pickle.dump(feature_importance, w_file)
    with open(
        os.path.join(
            config.RESULT_DIRECTORY, experiment, name, "classification_reports.pickle"
        ),
        "wb",
    ) as w_file:
        pickle.dump(classification_reports, w_file)


def fair_subsample(iterable, n, csize):
    i_copy = list(iterable)
    for i in range(n):
        comb = []
        for j in range(csize):
            if not i_copy:
                i_copy = list(iterable)
            randi = random.randint(0, len(i_copy) - 1)
            while i_copy[randi] in comb:
                randi = random.randint(0, len(i_copy) - 1)
            comb.append(i_copy.pop(randi))
        yield comb


def classify(experiment, plot):
    print("Loading dataset and labels")
    full = pd.read_pickle(
        os.path.join(config.DATASET_DIRECTORY, experiment, "dataset.pickle")
    )
    labels = pd.read_pickle(
        os.path.join(config.DATASET_DIRECTORY, experiment, "labels.pickle")
    )
    labels.index.names = ["sample_hash"]
    full = full.merge(labels[["family", "set"]], on="sample_hash", how="left")
    fullX = full.drop(["ms_elapsed", "set", "family"], axis=1)
    fully = full["family"]

    sample_ticks = [50, 60, 70]
    family_ticks = [70, 170, 270, 370, 470, 570]
    n_splits = 10
    families = list(set(fully))
    max_samples = 80
    grid_pieces = []
    grid_pieces.append(1)
    grid_pieces.append(n_splits * (len(sample_ticks) + len(family_ticks)))
    grid_pieces.append(len(sample_ticks) * len(family_ticks) * n_splits**2)
    grid_size = sum(grid_pieces)

    train_and_save_experiment = partial(train_and_save, experiment)

    print("Training and test classifiers")
    with tqdm(total=grid_size) as pbar:
        # Add 100% dataset
        train_and_save_experiment("ft_1-ff_0-st_1-sf_0", fullX, fully)
        pbar.update(1)

    # Decomment
    # #First split according to the number of samples
    # for sampleTick in sample_ticks:
    #     sampleFold=0
    #     samplesFold = model_selection.StratifiedShuffleSplit(n_splits=n_splits, train_size=sampleTick/max_samples)
    #     for train_index, _ in samplesFold.split(fullX,fully):
    #         sampleFiltered_X = fullX.iloc[train_index]
    #         sampleFiltered_y = fully.iloc[train_index]
    #         #Add % dataset with 100% families
    #         train_and_save_experiment(f'ft_1-ff_0-st_{sampleTick}-sf_{sampleFold}',sampleFiltered_X,sampleFiltered_y)
    #         pbar.update(1)

    #         #Second split according to the number of families
    #         for familyTick in family_ticks:
    #             familyFold = 0
    #             for retainedFamilies in fairSubsample(families, n_splits, familyTick):
    #                 familyFiltered_y = sampleFiltered_y[sampleFiltered_y.isin(retainedFamilies)]
    #                 familyFiltered_X = sampleFiltered_X.loc[familyFiltered_y.index]
    #                 #Add % families and % samples
    #                 train_and_save_experiment(f'ft_{familyTick}-ff_{familyFold}-st_{sampleTick}-sf_{sampleFold}',familyFiltered_X,familyFiltered_y)
    #                 pbar.update(1)
    #                 familyFold+=1
    #         sampleFold+=1

    # #Subsample families when samples are 100%
    # for familyTick in family_ticks:
    #     familyFold = 0
    #     for retainedFamilies in fairSubsample(families, n_splits, familyTick):
    #         familyFiltered_y = fully[fully.isin(retainedFamilies)]
    #         familyFiltered_X = fullX.loc[familyFiltered_y.index]
    #         #Add % families with 100% samples
    #         train_and_save_experiment(f'ft_{familyTick}-ff_{familyFold}-st_1-sf_0',familyFiltered_X,familyFiltered_y)
    #         pbar.update(1)
    #         familyFold+=1


def get_accuracy(experiment, path):
    # with open(os.path.join(config.RESULT_DIRECTORY,experiment,path,'trueLabel_predictedLabel_list.pickle'),'rb') as rFile:
    #     tp= pickle.load(rFile)
    with open(
        os.path.join(
            config.RESULT_DIRECTORY, experiment, path, "classificationReports.pickle"
        ),
        "rb",
    ) as rFile:
        reports = pickle.load(rFile)
    acc = []
    for report in reports:
        # acc.append(report['accuracy'].mean())
        acc.append(report["f1-score"].mean())
        # acc.append(report['precision'].mean())
        # acc.append(report['recall'].mean())
    return np.mean(acc)


def get_features(experiment, path):
    feature_partial = dict.fromkeys(config.FEAT_ALL.values())

    with open(
        os.path.join(
            config.RESULT_DIRECTORY, experiment, path, "featureImportance_list.pickle"
        ),
        "rb",
    ) as rFile:
        feature_importance = pickle.load(rFile)
    feature_importance = pd.concat(feature_importance, axis=1).mean(axis=1)
    current_importance = pd.DataFrame(
        0.0, index=config.FEAT_ALL.values(), columns=["feat_importance"]
    )
    # All feature type
    for prefix, name in config.FEAT_PREFIX.items():
        temp = feature_importance.loc[
            [x for x in feature_importance.index if x.startswith(prefix)]
        ]
        if path == "ft_1-ff_0-st_1-sf_0":
            feature_partial[name] = temp
        feature_importance = feature_importance.loc[
            ~feature_importance.index.isin(temp.index)
        ]
        current_importance.loc[name] = temp.sum()
    # Last is DLL
    current_importance.loc["dlls"] = feature_importance.sum()
    feature_partial["dlls"] = feature_importance

    feature_partial = {k: v for k, v in feature_partial.items() if "dynamic" not in k}
    for k, v in feature_partial.items():
        feature_partial[k] = v.sort_values(ascending=False).head(100)
        feature_partial[k].name = "Avg MDI Score"
        feature_partial[k].index.name = f"{k} feature"
        feature_partial[k].to_csv(
            os.path.join(
                config.RESULT_DIRECTORY,
                experiment,
                path,
                f"{k}_featureImportance_top100.tsv",
            ),
            sep="\t",
        )
    return current_importance


def check_family(d):
    return pd.Series([len(d), len(d[d.PredictedLabel == d.TrueLabel])])


def get_report(tple):
    experiment, path = tple
    best_and_worst = []
    with open(
        os.path.join(
            config.RESULT_DIRECTORY,
            experiment,
            path,
            "trueLabel_predictedLabel_list.pickle",
        ),
        "rb",
    ) as rFile:
        results = pickle.load(rFile)
        for result in results:
            grouped = result.groupby("TrueLabel").apply(check_family)
            grouped = grouped.rename(
                columns={0: "numPredicted", 1: "correctPredictions"}
            )
            best_and_worst.append(grouped)
    return best_and_worst, pd.concat(results).reset_index(drop=True)


def get_packing(tple):
    packed = pd.read_csv(os.path.join(config.DATASET_DIRECTORY, "packed.csv"))
    packed = packed.set_index("SHA256")
    packed["PACKER/PROTECTOR"] = packed["PACKER/PROTECTOR"].apply(
        lambda x: True if x == x else False
    )
    experiment, path = tple
    packed_res = []
    not_packed_res = []
    with open(
        os.path.join(
            config.RESULT_DIRECTORY,
            experiment,
            path,
            "trueLabel_predictedLabel_list.pickle",
        ),
        "rb",
    ) as rFile:
        results = pickle.load(rFile)
        for result in results:
            current_packed = result.reset_index().merge(
                packed["PACKER/PROTECTOR"], left_on="sample_hash", right_on="SHA256"
            )

            pk = current_packed[current_packed["PACKER/PROTECTOR"] == True].apply(
                lambda row: True
                if row["TrueLabel"] == row["PredictedLabel"]
                else False,
                axis=1,
            )
            pk_ratio = len(pk[pk]) / len(pk)
            packed_res.append(pk_ratio)
            npk = current_packed[current_packed["PACKER/PROTECTOR"] == False].apply(
                lambda row: True
                if row["TrueLabel"] == row["PredictedLabel"]
                else False,
                axis=1,
            )
            npk_ratio = len(npk[npk]) / len(npk)
            not_packed_res.append(npk_ratio)
    return np.mean(packed_res), np.mean(not_packed_res)


def misclassified_to_csv(group):
    tot_group = len(group)
    accuracy = (
        100 * len(group[group["TrueLabel"] == group["PredictedLabel"]]) / tot_group
    )
    family = list(set(group["TrueLabel"]))
    assert len(family) == 1
    family = family[0]
    group = group[group["PredictedLabel"] != family]
    other_predicted = len(set(group["PredictedLabel"]))
    breakdown = {
        k: 100 * v / tot_group for k, v in dict(Counter(group.PredictedLabel)).items()
    }
    breakdown = {
        k: v
        for k, v in sorted(breakdown.items(), key=lambda item: item[1], reverse=True)
    }
    breakdown = ",".join([f"{k},{v:.2f}" for k, v in breakdown.items()])
    return f"{tot_group},{accuracy:.2f},{other_predicted},{breakdown}\n"


def aggregate_results(experiment):
    # print('Generating the heatmap')
    # buildHeatmap(experiment)
    print("Computing features")
    build_features(experiment)
    # print('Ranking best and worst')
    # buildBestAndWorst(experiment)


def build_best_and_worst(experiment):
    all_predictions = []
    sample_ticks = [50, 60, 70, 80]
    family_ticks = [70, 170, 270, 370, 470, 570, 670]
    n_splits = 10
    sample_ticks = sample_ticks[:-1]
    family_ticks = family_ticks[:-1]

    # Add 100% dataset
    all_predictions.append((experiment, "ft_1-ff_0-st_1-sf_0"))

    # First split according to the number of samples
    for sample_tick in sample_ticks:
        for sample_fold in range(n_splits):
            all_predictions.append(
                (experiment, f"ft_1-ff_0-st_{sample_tick}-sf_{sample_fold}")
            )
            # Second split according to the number of families
            for family_tick in family_ticks:
                for family_fold in range(n_splits):
                    all_predictions.append(
                        (
                            experiment,
                            f"ft_{family_tick}-ff_{family_fold}-st_{sample_tick}-sf_{sample_fold}",
                        )
                    )

    # Subsample families when samples are 100%
    for family_tick in family_ticks:
        for family_fold in range(n_splits):
            all_predictions.append(
                (experiment, f"ft_{family_tick}-ff_{family_fold}-st_1-sf_0")
            )

    paired_results = p_map(get_report, all_predictions, num_cpus=config.CORES)
    unfiltred_results = [y for _, y in paired_results]
    all_results = [x for x, _ in paired_results]

    res = p_map(get_packing, all_predictions, num_cpus=config.CORES)
    one = []
    two = []
    for a, b in res:
        one.append(a)
        two.append(b)

    # Check worst families
    all_results = [item for sublist in all_results for item in sublist]
    all_results = reduce(lambda x, y: x.add(y, fill_value=0), all_results)
    all_results["correct"] = (
        100 * all_results["correctPredictions"] / all_results["numPredicted"]
    )
    all_results = all_results.sort_values(by="correct", ascending=True)

    # Static Vs Dynamic
    dynamic_results = pd.read_csv(
        "../features_Yufei/f1_acc_per_family.csv", sep="\t", index_col="family"
    )
    classes_families = pd.read_csv(
        "../features_Yufei/classes.sorted", sep="\t", index_col="family"
    )
    aggregated = (
        all_results.reset_index()
        .merge(dynamic_results, left_on="TrueLabel", right_on="family")
        .set_index("TrueLabel")
    )
    aggregated = (
        aggregated.reset_index()
        .merge(classes_families, left_on="TrueLabel", right_on="family")
        .set_index("TrueLabel")
    )
    aggregated = aggregated.rename(columns={"correct": "static", "accuracy": "dynamic"})
    aggregated = aggregated[["static", "dynamic", "class"]]
    fig, ax = plt.subplots()
    klasses = set(aggregated["class"])
    for c in klasses:
        current = aggregated[aggregated["class"] == c]
        ax.scatter(current["static"], current["dynamic"], s=1.5, label=c)
    ax.set_xlabel("Accuracy with static features", fontsize=15, labelpad=15)
    ax.set_ylabel("Accuracy with dynamic features", fontsize=15, labelpad=15)
    ax.set_xlim([0, 100])
    ax.set_ylim([0, 100])
    ax.legend()
    pc = round(np.corrcoef(aggregated["static"], aggregated["dynamic"])[0, 1], 2)
    print(f"All classes Pearson CC {pc} - families {len(aggregated)}")
    ax.set_title(f"All classes - Pearson correlation {pc}")
    fig.tight_layout()
    plt.savefig(
        os.path.join(
            config.RESULT_DIRECTORY, experiment, "static_dynamic_correlation.pdf"
        )
    )
    # Do this separate by class
    for c in klasses:
        fig, ax = plt.subplots()
        current = aggregated[aggregated["class"] == c]
        pc = round(np.corrcoef(current["static"], current["dynamic"])[0, 1], 2)
        print(f"{c} Pearson CC {pc} - families {len(current)}")
        ax.scatter(current["static"], current["dynamic"], s=1.5, label=c)
        ax.set_xlabel("Accuracy with static features", fontsize=15, labelpad=15)
        ax.set_ylabel("Accuracy with dynamic features", fontsize=15, labelpad=15)
        ax.legend()
        ax.set_title(f"Malware class: {c} - Pearson correlation {pc}")
        fig.tight_layout()
        plt.savefig(
            os.path.join(
                config.RESULT_DIRECTORY,
                experiment,
                f"static_dynamic_correlation_{c}.pdf",
            )
        )

    # Check mispredictions
    unfiltred_results = pd.concat(unfiltred_results).reset_index(drop=True)
    unfiltered_grouped = unfiltred_results.groupby("TrueLabel").apply(
        misclassified_to_csv
    )
    with open(
        os.path.join(config.RESULT_DIRECTORY, experiment, "misclassifies.csv"), "w"
    ) as w_file:
        for index, row in unfiltered_grouped.iteritems():
            w_file.write(index + "," + row)

    # Correlation with packed samples
    packed = pd.read_csv(os.path.join(config.DATASET_DIRECTORY, "packed.csv"))
    packed = packed.set_index("SHA256")
    packed = (
        packed.groupby("FAMILY")
        .agg(lambda x: len(x[~x.isna()]) / len(x))
        .sort_values(by="PACKER/PROTECTOR", ascending=False)
    )
    packed = (
        packed.reset_index()
        .merge(all_results["correct"], left_on="FAMILY", right_on="TrueLabel")
        .set_index("FAMILY")
    )
    fig, ax = plt.subplots()
    ax.scatter(packed["PACKER/PROTECTOR"], packed["correct"], s=1.5)
    ax.set_xlabel("% packed/protected samples", fontsize=15, labelpad=15)
    ax.set_ylabel("\% accuracy", fontsize=15, labelpad=15)
    fig.tight_layout()
    plt.savefig(
        os.path.join(config.RESULT_DIRECTORY, experiment, "packing_correlation.pdf")
    )

    # Correlation with AVclass confidence
    avclass_confidence = pd.read_csv(
        config.AVCLASS_AGREEMENT, sep="\t", index_col="sha2"
    )
    confidence_metric1 = (
        avclass_confidence[["final_avc2_family", "av_cnt_ratio_over_labels"]]
        .groupby("final_avc2_family")
        .mean()
    )
    confidence_metric1_result = pd.concat(
        [
            all_results,
            confidence_metric1[confidence_metric1.index.isin(all_results.index)],
        ],
        axis=1,
    )
    pearson = round(
        np.corrcoef(
            confidence_metric1_result["av_cnt_ratio_over_labels"].tail(40),
            confidence_metric1_result["correct"].tail(40),
        )[0, 1],
        2,
    )
    import IPython

    IPython.embed(colors="Linux")
    fig, ax = plt.subplots()
    ax.scatter(
        confidence_metric1_result["av_cnt_ratio_over_labels"],
        confidence_metric1_result["correct"],
        s=1.5,
    )
    ax.set_xlabel("AV count ratio over labels", fontsize=15, labelpad=15)
    ax.set_ylabel("\% accuracy", fontsize=15, labelpad=15)
    fig.tight_layout()
    plt.savefig(
        os.path.join(
            config.RESULT_DIRECTORY, experiment, "avClassConfidence_correlation.pdf"
        )
    )

    # Putting everything together for the table
    # The following two lines are for dynamic results
    # all_results = dynamic_results.rename(columns={'f1':'correct'})
    # all_results.index.names = ['TrueLabel']
    # END The following two lines are for dynamic results

    all_results = all_results.reset_index().merge(
        classes_families["class"], left_on="TrueLabel", right_on="family"
    )
    all_results = all_results[["TrueLabel", "correct", "class"]]
    all_results = all_results.merge(
        packed["PACKER/PROTECTOR"], left_on="TrueLabel", right_on="FAMILY"
    )
    print(
        f"Correlation between correct predictions and packing is {np.corrcoef(all_results['correct'], all_results['PACKER/PROTECTOR'])}"
    )
    all_results = all_results.set_index("TrueLabel")
    all_results.index.names = ["Family"]
    all_results = all_results.rename(
        columns={
            "correct": "Avg Accuracy",
            "class": "Class",
            "PACKER/PROTECTOR": "% packed",
        }
    )
    all_results = all_results[["Class", "Avg Accuracy", "% packed"]]
    all_results["Avg Accuracy"] = round(all_results["Avg Accuracy"], 3)
    all_results = all_results.sort_values(by="Avg Accuracy")
    all_results.to_latex(
        os.path.join(
            config.RESULT_DIRECTORY,
            experiment,
            "tbl_multiclass_bestAndWorst_dynamic.tex",
        )
    )
    # Group
    grouped = all_results.groupby("Class").agg("mean")["Avg Accuracy"]
    grouped.to_latex(
        os.path.join(
            config.RESULT_DIRECTORY,
            experiment,
            "tbl_multiclass_bestAndWorst_grouped_dynamic.tex",
        )
    )


def build_features(experiment):
    sample_ticks = [50, 60, 70, 80]
    family_ticks = [70, 170, 270, 370, 470, 570, 670]
    n_splits = 10
    heatmap = pd.DataFrame(0.0, index=sample_ticks, columns=family_ticks)
    heatmap.index.names = ["samples"]
    feat_tbl = dict.fromkeys(xprod(sample_ticks, family_ticks))
    sample_ticks = sample_ticks[:-1]
    family_ticks = family_ticks[:-1]
    mean = dict.fromkeys(family_ticks)
    for k in mean.keys():
        mean[k] = []

    # Add 100% dataset
    feat_tbl[(80, 670)] = get_features(experiment, "ft_1-ff_0-st_1-sf_0")
    print(feat_tbl[(80, 670)])
    return

    # First split according to the number of samples
    for sample_tick in sample_ticks:
        feat_ = []
        t_mean = mean.copy()
        for sample_fold in range(n_splits):
            feat_.append(
                get_features(experiment, f"ft_1-ff_0-st_{sample_tick}-sf_{sample_fold}")
            )
            # Second split according to the number of families
            for family_tick in family_ticks:
                for family_fold in range(n_splits):
                    t_mean[family_tick].append(
                        get_features(
                            experiment,
                            f"ft_{family_tick}-ff_{family_fold}-st_{sample_tick}-sf_{sample_fold}",
                        )
                    )
        feat_tbl[(sample_tick, 670)] = pd.concat(feat_, axis=1).mean(axis=1)
        for k, v in t_mean.items():
            feat_tbl[(sample_tick, k)] = pd.concat(v, axis=1).mean(axis=1)

    # Subsample families when samples are 100%
    for family_tick in family_ticks:
        feat = []
        for family_fold in range(n_splits):
            feat_.append(
                get_features(experiment, f"ft_{family_tick}-ff_{family_fold}-st_1-sf_0")
            )
        feat_tbl[(80, family_tick)] = pd.concat(v, axis=1).mean(axis=1)

    avg_table = []
    for feature in config.FEAT_ALL.values():
        current_heatmap = heatmap.copy()
        for family_tick in heatmap.columns:
            for sample_tick in heatmap.index:
                avg_table.append(feat_tbl[(sample_tick, family_tick)])
                current_heatmap.at[sample_tick, family_tick] = feat_tbl[
                    (sample_tick, family_tick)
                ].loc[feature]
        fig, ax = plt.subplots()
        sns.heatmap(
            current_heatmap,
            linewidths=0.7,
            annot=True,
            fmt=".3f",
            square=True,
            annot_kws={"fontsize": 12},
            cbar_kws={"orientation": "horizontal", "pad": 0.2},
            ax=ax,
        )
        ax.set_xlabel("Families", fontsize=15, labelpad=15)
        ax.set_ylabel("Samples", fontsize=15, labelpad=15)
        fig.tight_layout()
        plt.savefig(
            os.path.join(
                config.RESULT_DIRECTORY, experiment, f"feat_importance_{feature}.pdf"
            )
        )
    avg_table = pd.concat(avg_table, axis=1).mean(axis=1)
    avg_table.to_latex(
        os.path.join(
            config.RESULT_DIRECTORY, experiment, "feat_importance_multiclass.tex"
        )
    )


def build_heatmap(experiment):
    sample_ticks = [50, 60, 70, 80]
    family_ticks = [70, 170, 270, 370, 470, 570, 670]
    n_splits = 10
    heatmap = pd.DataFrame(0.0, index=sample_ticks, columns=family_ticks)
    heatmap.index.names = ["samples"]
    sample_ticks = sample_ticks[:-1]
    family_ticks = family_ticks[:-1]
    mean = dict.fromkeys(family_ticks)
    for k in mean.keys():
        mean[k] = []

    # Add 100% dataset
    heatmap.loc[80, 670] = get_accuracy(experiment, "ft_1-ff_0-st_1-sf_0")

    # First split according to the number of samples
    for sampleTick in sample_ticks:
        accuracy_ = []
        t_mean = mean.copy()
        for sampleFold in range(n_splits):
            accuracy_.append(
                get_accuracy(experiment, f"ft_1-ff_0-st_{sampleTick}-sf_{sampleFold}")
            )
            # Second split according to the number of families
            for family_tick in family_ticks:
                for family_fold in range(n_splits):
                    t_mean[family_tick].append(
                        get_accuracy(
                            experiment,
                            f"ft_{family_tick}-ff_{family_fold}-st_{sampleTick}-sf_{sampleFold}",
                        )
                    )
        heatmap.loc[sampleTick, 670] = np.mean(accuracy_)
        for k, v in t_mean.items():
            heatmap.loc[sampleTick, k] = np.mean(v)

    # Subsample families when samples are 100%
    for family_tick in family_ticks:
        accuracy_ = []
        for family_fold in range(n_splits):
            accuracy_.append(
                get_accuracy(experiment, f"ft_{family_tick}-ff_{family_fold}-st_1-sf_0")
            )
        heatmap.loc[80, family_tick] = np.mean(accuracy_)

    plot = sns.heatmap(
        heatmap,
        linewidths=0.7,
        annot=True,
        fmt=".3f",
        square=True,
        annot_kws={"fontsize": 12},
        cbar_kws={"orientation": "horizontal", "pad": 0.2},
    )
    # plt.title('Classifier accuracy score', fontsize = 15)
    plt.xlabel("Families", fontsize=15, labelpad=15)
    plt.ylabel("Samples", fontsize=15, labelpad=15)
    plt.tight_layout()
    plt.savefig(
        os.path.join(config.RESULT_DIRECTORY, experiment, "f1-score-heatmap.pdf")
    )
    # plt.savefig(os.path.join(config.RESULT_DIRECTORY,experiment,'accuracy-heatmap.pdf'))
