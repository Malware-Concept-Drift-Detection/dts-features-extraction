from tqdm import tqdm
from p_tqdm import p_map
import config
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


def padConfusionMatrix(cm):
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


def trainAndSave(experiment, name, X, y):
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
        n_jobs=72,
        max_depth=None,
        n_estimators=225,
        max_features='sqrt')

    classificationResult = []
    probabilityResult = []
    confusion_matrix = []
    feature_importance = []
    classificationReports = []
    clfs = []

    n_splits = 5
    kfold = model_selection.StratifiedShuffleSplit(n_splits=n_splits, test_size=.2)
    for train_index, test_index in kfold.split(X, y):
        # Compute and Save each round
        X_train = X.iloc[train_index]
        X_test = X.iloc[test_index]
        y_train = y.iloc[train_index]
        y_test = y.iloc[test_index]
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_proba = clf.predict_proba(X_test)
        if name == 'ft_1-ff_0-st_1-sf_0':
            clfs.append(clf)

        # Prediction Probability
        currentProbability = pd.DataFrame(y_test)
        currentProbability.loc[:, clf.classes_] = y_proba
        currentProbability['Entropy'] = currentProbability[clf.classes_].apply(entropy, axis=1)
        probabilityResult.append(currentProbability)

        # Prediction result
        currentResult = pd.DataFrame(y_test)
        currentResult.index.names = ['sample_hash']
        currentResult['PredictedLabel'] = y_pred
        currentResult = currentResult.rename(columns={'family': 'TrueLabel'})
        classificationResult.append(currentResult)

        # Confusion Matrix
        currentCM = pd.crosstab(y_test, y_pred, rownames=['True Value'], colnames=['Predicted Value'],
                                normalize='index')
        currentCM = padConfusionMatrix(currentCM)
        confusion_matrix.append(currentCM)

        # Feature Importance
        currentImportance = pd.DataFrame(clf.feature_importances_, index=X_train.columns,
                                         columns=['feat_importance']).sort_values(by='feat_importance', ascending=False)
        feature_importance.append(currentImportance)

        # Classification parameters
        currentReport = pd.DataFrame(classification_report(y_test, y_pred, output_dict=True))
        currentReport = currentReport.swapaxes('index', 'columns')
        currentReport = currentReport.drop(['accuracy', 'macro avg', 'weighted avg'])
        currentReport = currentReport.drop(['support'], axis=1)
        currentReport['accuracy'] = 0.00
        for family in currentReport.index:
            currentReport.at[family, 'accuracy'] = currentCM.at[family, family]
        currentReport.index.names = ['name']
        classificationReports.append(currentReport)

    # Save results
    if name == 'ft_1-ff_0-st_1-sf_0':
        with open(os.path.join(config.RESULT_DIRECTORY, experiment, name, 'classifiers.pickle'), 'wb') as wFile:
            pickle.dump(clfs, wFile)
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, name, 'trueLabel_probability_list.pickle'),
              'wb') as wFile:
        pickle.dump(probabilityResult, wFile)
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, name, 'trueLabel_predictedLabel_list.pickle'),
              'wb') as wFile:
        pickle.dump(classificationResult, wFile)
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, name, 'confusionMatrix_list.pickle'), 'wb') as wFile:
        pickle.dump(confusion_matrix, wFile)
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, name, 'featureImportance_list.pickle'), 'wb') as wFile:
        pickle.dump(feature_importance, wFile)
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, name, 'classificationReports.pickle'), 'wb') as wFile:
        pickle.dump(classificationReports, wFile)


def fairSubsample(iterable, n, csize):
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
    full = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'dataset.pickle'))
    labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment, 'labels.pickle'))
    labels.index.names = ['sample_hash']
    full = full.merge(labels[['family', 'set']], on='sample_hash', how='left')
    fullX = full.drop(['ms_elapsed', 'set', 'family'], axis=1)
    fully = full['family']

    sampleTicks = [50, 60, 70]
    familyTicks = [70, 170, 270, 370, 470, 570]
    n_splits = 10
    families = list(set(fully))
    maxSamples = 80
    gridPieces = []
    gridPieces.append(1)
    gridPieces.append(n_splits * (len(sampleTicks) + len(familyTicks)))
    gridPieces.append(len(sampleTicks) * len(familyTicks) * n_splits ** 2)
    gridSize = sum(gridPieces)

    trainAndSaveExperiment = partial(trainAndSave, experiment)

    print("Training and test classifiers")
    with tqdm(total=gridSize) as pbar:
        # Add 100% dataset
        trainAndSaveExperiment('ft_1-ff_0-st_1-sf_0', fullX, fully)
        pbar.update(1)

    # Decomment
    # #First split according to the number of samples
    # for sampleTick in sampleTicks:
    #     sampleFold=0
    #     samplesFold = model_selection.StratifiedShuffleSplit(n_splits=n_splits, train_size=sampleTick/maxSamples)
    #     for train_index, _ in samplesFold.split(fullX,fully):
    #         sampleFiltered_X = fullX.iloc[train_index]
    #         sampleFiltered_y = fully.iloc[train_index]
    #         #Add % dataset with 100% families
    #         trainAndSaveExperiment(f'ft_1-ff_0-st_{sampleTick}-sf_{sampleFold}',sampleFiltered_X,sampleFiltered_y)
    #         pbar.update(1)

    #         #Second split according to the number of families
    #         for familyTick in familyTicks:
    #             familyFold = 0
    #             for retainedFamilies in fairSubsample(families, n_splits, familyTick):
    #                 familyFiltered_y = sampleFiltered_y[sampleFiltered_y.isin(retainedFamilies)]
    #                 familyFiltered_X = sampleFiltered_X.loc[familyFiltered_y.index]
    #                 #Add % families and % samples
    #                 trainAndSaveExperiment(f'ft_{familyTick}-ff_{familyFold}-st_{sampleTick}-sf_{sampleFold}',familyFiltered_X,familyFiltered_y)
    #                 pbar.update(1)
    #                 familyFold+=1
    #         sampleFold+=1

    # #Subsample families when samples are 100%
    # for familyTick in familyTicks:
    #     familyFold = 0
    #     for retainedFamilies in fairSubsample(families, n_splits, familyTick):
    #         familyFiltered_y = fully[fully.isin(retainedFamilies)]
    #         familyFiltered_X = fullX.loc[familyFiltered_y.index]
    #         #Add % families with 100% samples
    #         trainAndSaveExperiment(f'ft_{familyTick}-ff_{familyFold}-st_1-sf_0',familyFiltered_X,familyFiltered_y)
    #         pbar.update(1)
    #         familyFold+=1


def getAccuracy(experiment, path):
    # with open(os.path.join(config.RESULT_DIRECTORY,experiment,path,'trueLabel_predictedLabel_list.pickle'),'rb') as rFile:
    #     tp= pickle.load(rFile)
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, path, 'classificationReports.pickle'), 'rb') as rFile:
        reports = pickle.load(rFile)
    acc = []
    for report in reports:
        # acc.append(report['accuracy'].mean())
        acc.append(report['f1-score'].mean())
        # acc.append(report['precision'].mean())
        # acc.append(report['recall'].mean())
    return np.mean(acc)


def getFeatures(experiment, path):
    featurePartial = dict.fromkeys(config.FEAT_ALL.values())

    with open(os.path.join(config.RESULT_DIRECTORY, experiment, path, 'featureImportance_list.pickle'), 'rb') as rFile:
        feature_importance = pickle.load(rFile)
    feature_importance = pd.concat(feature_importance, axis=1).mean(axis=1)
    currentImportance = pd.DataFrame(0.0, index=config.FEAT_ALL.values(), columns=['feat_importance'])
    # All feature type
    for prefix, name in config.FEAT_PREFIX.items():
        temp = feature_importance.loc[[x for x in feature_importance.index if x.startswith(prefix)]]
        if path == 'ft_1-ff_0-st_1-sf_0':
            featurePartial[name] = temp
        feature_importance = feature_importance.loc[~feature_importance.index.isin(temp.index)]
        currentImportance.loc[name] = temp.sum()
    # Last is DLL
    currentImportance.loc['dlls'] = feature_importance.sum()
    featurePartial['dlls'] = feature_importance

    featurePartial = {k: v for k, v in featurePartial.items() if 'dynamic' not in k}
    for k, v in featurePartial.items():
        featurePartial[k] = v.sort_values(ascending=False).head(100)
        featurePartial[k].name = 'Avg MDI Score'
        featurePartial[k].index.name = f'{k} feature'
        featurePartial[k].to_csv(
            os.path.join(config.RESULT_DIRECTORY, experiment, path, f'{k}_featureImportance_top100.tsv'), sep='\t')
    return currentImportance


def checkFamily(d):
    return pd.Series([len(d), len(d[d.PredictedLabel == d.TrueLabel])])


def getReport(tple):
    experiment, path = tple
    bestAndWorst = []
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, path, 'trueLabel_predictedLabel_list.pickle'),
              'rb') as rFile:
        results = pickle.load(rFile)
        for result in results:
            grouped = result.groupby('TrueLabel').apply(checkFamily)
            grouped = grouped.rename(columns={0: 'numPredicted', 1: 'correctPredictions'})
            bestAndWorst.append(grouped)
    return bestAndWorst, pd.concat(results).reset_index(drop=True)


def getPacking(tple):
    packed = pd.read_csv(os.path.join(config.DATASET_DIRECTORY, 'packed.csv'))
    packed = packed.set_index('SHA256')
    packed['PACKER/PROTECTOR'] = packed['PACKER/PROTECTOR'].apply(lambda x: True if x == x else False)
    experiment, path = tple
    packedRes = []
    notPackedRes = []
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, path, 'trueLabel_predictedLabel_list.pickle'),
              'rb') as rFile:
        results = pickle.load(rFile)
        for result in results:
            currentPacked = result.reset_index().merge(packed['PACKER/PROTECTOR'], left_on='sample_hash',
                                                       right_on='SHA256')

            pk = currentPacked[currentPacked['PACKER/PROTECTOR'] == True].apply(
                lambda row: True if row['TrueLabel'] == row['PredictedLabel'] else False, axis=1)
            pkRatio = len(pk[pk]) / len(pk)
            packedRes.append(pkRatio)
            npk = currentPacked[currentPacked['PACKER/PROTECTOR'] == False].apply(
                lambda row: True if row['TrueLabel'] == row['PredictedLabel'] else False, axis=1)
            npkRatio = len(npk[npk]) / len(npk)
            notPackedRes.append(npkRatio)
    return np.mean(packedRes), np.mean(notPackedRes)


def misclassifiedToCSV(group):
    totGroup = len(group)
    accuracy = 100 * len(group[group['TrueLabel'] == group['PredictedLabel']]) / totGroup
    family = list(set(group['TrueLabel']))
    assert len(family) == 1
    family = family[0]
    group = group[group['PredictedLabel'] != family]
    otherPredicted = len(set(group['PredictedLabel']))
    breakdown = {k: 100 * v / totGroup for k, v in dict(Counter(group.PredictedLabel)).items()}
    breakdown = {k: v for k, v in sorted(breakdown.items(), key=lambda item: item[1], reverse=True)}
    breakdown = ",".join([f'{k},{v:.2f}' for k, v in breakdown.items()])
    return f'{totGroup},{accuracy:.2f},{otherPredicted},{breakdown}\n'


def aggregateResults(experiment):
    # print('Generating the heatmap')
    # buildHeatmap(experiment)
    print('Computing features')
    buildFeatures(experiment)
    # print('Ranking best and worst')
    # buildBestAndWorst(experiment)


def buildBestAndWorst(experiment):
    allPredictions = []
    sampleTicks = [50, 60, 70, 80]
    familyTicks = [70, 170, 270, 370, 470, 570, 670]
    n_splits = 10
    sampleTicks = sampleTicks[:-1]
    familyTicks = familyTicks[:-1]

    # Add 100% dataset
    allPredictions.append((experiment, 'ft_1-ff_0-st_1-sf_0'))

    # First split according to the number of samples
    for sampleTick in sampleTicks:
        for sampleFold in range(n_splits):
            allPredictions.append((experiment, f'ft_1-ff_0-st_{sampleTick}-sf_{sampleFold}'))
            # Second split according to the number of families
            for familyTick in familyTicks:
                for familyFold in range(n_splits):
                    allPredictions.append(
                        (experiment, f'ft_{familyTick}-ff_{familyFold}-st_{sampleTick}-sf_{sampleFold}'))

    # Subsample families when samples are 100%
    for familyTick in familyTicks:
        for familyFold in range(n_splits):
            allPredictions.append((experiment, f'ft_{familyTick}-ff_{familyFold}-st_1-sf_0'))

    pairedResults = p_map(getReport, allPredictions, num_cpus=config.CORES)
    unfiltredResults = [y for _, y in pairedResults]
    allResults = [x for x, _ in pairedResults]

    res = p_map(getPacking, allPredictions, num_cpus=config.CORES)
    one = []
    two = []
    for a, b in res:
        one.append(a)
        two.append(b)

    # Check worst families
    allResults = [item for sublist in allResults for item in sublist]
    allResults = reduce(lambda x, y: x.add(y, fill_value=0), allResults)
    allResults['correct'] = 100 * allResults['correctPredictions'] / allResults['numPredicted']
    allResults = allResults.sort_values(by='correct', ascending=True)

    # Static Vs Dynamic
    dynamicResults = pd.read_csv('../features_Yufei/f1_acc_per_family.csv', sep='\t', index_col='family')
    classesFamilies = pd.read_csv('../features_Yufei/classes.sorted', sep='\t', index_col='family')
    aggregated = allResults.reset_index().merge(dynamicResults, left_on="TrueLabel", right_on="family").set_index(
        'TrueLabel')
    aggregated = aggregated.reset_index().merge(classesFamilies, left_on="TrueLabel", right_on="family").set_index(
        'TrueLabel')
    aggregated = aggregated.rename(columns={'correct': 'static', 'accuracy': 'dynamic'})
    aggregated = aggregated[['static', 'dynamic', 'class']]
    fig, ax = plt.subplots()
    klasses = set(aggregated['class'])
    for c in klasses:
        current = aggregated[aggregated['class'] == c]
        ax.scatter(current['static'], current['dynamic'], s=1.5, label=c)
    ax.set_xlabel('Accuracy with static features', fontsize=15, labelpad=15)
    ax.set_ylabel('Accuracy with dynamic features', fontsize=15, labelpad=15)
    ax.set_xlim([0, 100])
    ax.set_ylim([0, 100])
    ax.legend()
    pc = round(np.corrcoef(aggregated['static'], aggregated['dynamic'])[0, 1], 2)
    print(f'All classes Pearson CC {pc} - families {len(aggregated)}')
    ax.set_title(f'All classes - Pearson correlation {pc}')
    fig.tight_layout()
    plt.savefig(os.path.join(config.RESULT_DIRECTORY, experiment, 'static_dynamic_correlation.pdf'))
    # Do this separate by class
    for c in klasses:
        fig, ax = plt.subplots()
        current = aggregated[aggregated['class'] == c]
        pc = round(np.corrcoef(current['static'], current['dynamic'])[0, 1], 2)
        print(f'{c} Pearson CC {pc} - families {len(current)}')
        ax.scatter(current['static'], current['dynamic'], s=1.5, label=c)
        ax.set_xlabel('Accuracy with static features', fontsize=15, labelpad=15)
        ax.set_ylabel('Accuracy with dynamic features', fontsize=15, labelpad=15)
        ax.legend()
        ax.set_title(f'Malware class: {c} - Pearson correlation {pc}')
        fig.tight_layout()
        plt.savefig(os.path.join(config.RESULT_DIRECTORY, experiment, f'static_dynamic_correlation_{c}.pdf'))

    # Check mispredictions
    unfiltredResults = pd.concat(unfiltredResults).reset_index(drop=True)
    unfilteredGrouped = unfiltredResults.groupby('TrueLabel').apply(misclassifiedToCSV)
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, 'misclassifies.csv'), 'w') as wFile:
        for index, row in unfilteredGrouped.iteritems():
            wFile.write(index + "," + row)

    # Correlation with packed samples
    packed = pd.read_csv(os.path.join(config.DATASET_DIRECTORY, 'packed.csv'))
    packed = packed.set_index('SHA256')
    packed = packed.groupby('FAMILY').agg(lambda x: len(x[~x.isna()]) / len(x)).sort_values(by='PACKER/PROTECTOR',
                                                                                            ascending=False)
    packed = packed.reset_index().merge(allResults['correct'], left_on='FAMILY', right_on='TrueLabel').set_index(
        'FAMILY')
    fig, ax = plt.subplots()
    ax.scatter(packed['PACKER/PROTECTOR'], packed['correct'], s=1.5)
    ax.set_xlabel('% packed/protected samples', fontsize=15, labelpad=15)
    ax.set_ylabel('\% accuracy', fontsize=15, labelpad=15)
    fig.tight_layout()
    plt.savefig(os.path.join(config.RESULT_DIRECTORY, experiment, 'packing_correlation.pdf'))

    # Correlation with AVclass confidence
    avclassConfidence = pd.read_csv(config.AVCLASS_AGREEMENT, sep='\t', index_col='sha2')
    confidenceMetric1 = avclassConfidence[['final_avc2_family', 'av_cnt_ratio_over_labels']].groupby(
        'final_avc2_family').mean()
    confidenceMetric1Result = pd.concat([allResults, confidenceMetric1[confidenceMetric1.index.isin(allResults.index)]],
                                        axis=1)
    pearson = round(np.corrcoef(confidenceMetric1Result['av_cnt_ratio_over_labels'].tail(40),
                                confidenceMetric1Result['correct'].tail(40))[0, 1], 2)
    import IPython
    IPython.embed(colors='Linux')
    fig, ax = plt.subplots()
    ax.scatter(confidenceMetric1Result['av_cnt_ratio_over_labels'], confidenceMetric1Result['correct'], s=1.5)
    ax.set_xlabel('AV count ratio over labels', fontsize=15, labelpad=15)
    ax.set_ylabel('\% accuracy', fontsize=15, labelpad=15)
    fig.tight_layout()
    plt.savefig(os.path.join(config.RESULT_DIRECTORY, experiment, 'avClassConfidence_correlation.pdf'))

    # Putting everything together for the table
    # The following two lines are for dynamic results
    # allResults = dynamicResults.rename(columns={'f1':'correct'})
    # allResults.index.names = ['TrueLabel']
    # END The following two lines are for dynamic results

    allResults = allResults.reset_index().merge(classesFamilies['class'], left_on='TrueLabel', right_on='family')
    allResults = allResults[['TrueLabel', 'correct', 'class']]
    allResults = allResults.merge(packed['PACKER/PROTECTOR'], left_on='TrueLabel', right_on='FAMILY')
    print(
        f"Correlation between correct predictions and packing is {np.corrcoef(allResults['correct'], allResults['PACKER/PROTECTOR'])}")
    allResults = allResults.set_index('TrueLabel')
    allResults.index.names = ['Family']
    allResults = allResults.rename(
        columns={'correct': 'Avg Accuracy', 'class': 'Class', 'PACKER/PROTECTOR': '% packed'})
    allResults = allResults[['Class', 'Avg Accuracy', '% packed']]
    allResults['Avg Accuracy'] = round(allResults['Avg Accuracy'], 3)
    allResults = allResults.sort_values(by='Avg Accuracy')
    allResults.to_latex(os.path.join(config.RESULT_DIRECTORY, experiment, 'tbl_multiclass_bestAndWorst_dynamic.tex'))
    # Group
    grouped = allResults.groupby('Class').agg('mean')['Avg Accuracy']
    grouped.to_latex(
        os.path.join(config.RESULT_DIRECTORY, experiment, 'tbl_multiclass_bestAndWorst_grouped_dynamic.tex'))


def buildFeatures(experiment):
    sampleTicks = [50, 60, 70, 80]
    familyTicks = [70, 170, 270, 370, 470, 570, 670]
    n_splits = 10
    heatmap = pd.DataFrame(0.0, index=sampleTicks, columns=familyTicks)
    heatmap.index.names = ['samples']
    feat_tbl = dict.fromkeys(xprod(sampleTicks, familyTicks))
    sampleTicks = sampleTicks[:-1]
    familyTicks = familyTicks[:-1]
    mean = dict.fromkeys(familyTicks)
    for k in mean.keys():
        mean[k] = []

    # Add 100% dataset
    feat_tbl[(80, 670)] = getFeatures(experiment, 'ft_1-ff_0-st_1-sf_0')
    print(feat_tbl[(80, 670)])
    return

    # First split according to the number of samples
    for sampleTick in sampleTicks:
        feat_ = []
        tMean = mean.copy()
        for sampleFold in range(n_splits):
            feat_.append(getFeatures(experiment, f'ft_1-ff_0-st_{sampleTick}-sf_{sampleFold}'))
            # Second split according to the number of families
            for familyTick in familyTicks:
                for familyFold in range(n_splits):
                    tMean[familyTick].append(
                        getFeatures(experiment, f'ft_{familyTick}-ff_{familyFold}-st_{sampleTick}-sf_{sampleFold}'))
        feat_tbl[(sampleTick, 670)] = pd.concat(feat_, axis=1).mean(axis=1)
        for k, v in tMean.items():
            feat_tbl[(sampleTick, k)] = pd.concat(v, axis=1).mean(axis=1)

    # Subsample families when samples are 100%
    for familyTick in familyTicks:
        feat = []
        for familyFold in range(n_splits):
            feat_.append(getFeatures(experiment, f'ft_{familyTick}-ff_{familyFold}-st_1-sf_0'))
        feat_tbl[(80, familyTick)] = pd.concat(v, axis=1).mean(axis=1)

    avg_table = []
    for feature in config.FEAT_ALL.values():
        currentHeatmap = heatmap.copy()
        for familyTick in heatmap.columns:
            for sampleTick in heatmap.index:
                avg_table.append(feat_tbl[(sampleTick, familyTick)])
                currentHeatmap.at[sampleTick, familyTick] = feat_tbl[(sampleTick, familyTick)].loc[feature]
        fig, ax = plt.subplots()
        sns.heatmap(currentHeatmap, linewidths=0.7, annot=True, fmt=".3f", square=True, annot_kws={"fontsize": 12},
                    cbar_kws={"orientation": "horizontal", "pad": 0.2}, ax=ax)
        ax.set_xlabel('Families', fontsize=15, labelpad=15)
        ax.set_ylabel('Samples', fontsize=15, labelpad=15)
        fig.tight_layout()
        plt.savefig(os.path.join(config.RESULT_DIRECTORY, experiment, f'feat_importance_{feature}.pdf'))
    avg_table = pd.concat(avg_table, axis=1).mean(axis=1)
    avg_table.to_latex(os.path.join(config.RESULT_DIRECTORY, experiment, 'feat_importance_multiclass.tex'))


def buildHeatmap(experiment):
    sampleTicks = [50, 60, 70, 80]
    familyTicks = [70, 170, 270, 370, 470, 570, 670]
    n_splits = 10
    heatmap = pd.DataFrame(0.0, index=sampleTicks, columns=familyTicks)
    heatmap.index.names = ['samples']
    sampleTicks = sampleTicks[:-1]
    familyTicks = familyTicks[:-1]
    mean = dict.fromkeys(familyTicks)
    for k in mean.keys():
        mean[k] = []

    # Add 100% dataset
    heatmap.loc[80, 670] = getAccuracy(experiment, 'ft_1-ff_0-st_1-sf_0')

    # First split according to the number of samples
    for sampleTick in sampleTicks:
        accuracy_ = []
        tMean = mean.copy()
        for sampleFold in range(n_splits):
            accuracy_.append(getAccuracy(experiment, f'ft_1-ff_0-st_{sampleTick}-sf_{sampleFold}'))
            # Second split according to the number of families
            for familyTick in familyTicks:
                for familyFold in range(n_splits):
                    tMean[familyTick].append(
                        getAccuracy(experiment, f'ft_{familyTick}-ff_{familyFold}-st_{sampleTick}-sf_{sampleFold}'))
        heatmap.loc[sampleTick, 670] = np.mean(accuracy_)
        for k, v in tMean.items():
            heatmap.loc[sampleTick, k] = np.mean(v)

    # Subsample families when samples are 100%
    for familyTick in familyTicks:
        accuracy_ = []
        for familyFold in range(n_splits):
            accuracy_.append(getAccuracy(experiment, f'ft_{familyTick}-ff_{familyFold}-st_1-sf_0'))
        heatmap.loc[80, familyTick] = np.mean(accuracy_)

    plot = sns.heatmap(heatmap, linewidths=0.7, annot=True, fmt=".3f", square=True, annot_kws={"fontsize": 12},
                       cbar_kws={"orientation": "horizontal", "pad": 0.2})
    # plt.title('Classifier accuracy score', fontsize = 15) 
    plt.xlabel('Families', fontsize=15, labelpad=15)
    plt.ylabel('Samples', fontsize=15, labelpad=15)
    plt.tight_layout()
    plt.savefig(os.path.join(config.RESULT_DIRECTORY, experiment, 'f1-score-heatmap.pdf'))
    # plt.savefig(os.path.join(config.RESULT_DIRECTORY,experiment,'accuracy-heatmap.pdf'))
