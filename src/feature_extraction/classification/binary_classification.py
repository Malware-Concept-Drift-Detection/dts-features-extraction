from tqdm import tqdm
from src.feature_extraction import config
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_curve, auc, classification_report
from sklearn import model_selection
import pickle
from functools import reduce


def classify(experiment, plot):
    for r in [str(x) for x in range(5)]:
        print(f"Loading dataset and labels. Round {r}")
        full = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment + '/' + r, 'dataset.pickle'))
        try:
            full = full.drop('pesectionProcessed_entrypointSection_name', axis=1)
        except:
            pass
        labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY, experiment + '/' + r, 'labels.pickle'))
        labels.index.names = ['sample_hash']
        full = full.merge(labels[['benign', 'family', 'set']], on='sample_hash', how='left')
        X = full.drop(['ms_elapsed', 'set', 'family', 'benign'], axis=1)
        y = full[['benign', 'family']]
        # This is only for packed only binary
        y['family'] = y['family'].apply(lambda x: 'malware' if x else 'goodware')
        # This is only for packed only binary

        print("Training the classifier")
        clf = RandomForestClassifier(
            n_jobs=config.CORES,
            max_depth=None,
            n_estimators=225,
            max_features='sqrt')

        classification_result = []
        classification_reports = []
        confusion_matrix = []
        feature_importance = []
        tprs = []
        aucs = []
        mean_fpr = np.linspace(0, 1, 100)

        n_splits = 10
        kfold = model_selection.StratifiedShuffleSplit(n_splits=n_splits, test_size=.2)

        fold = 0
        for train_index, test_index in tqdm(kfold.split(X, y), total=n_splits):

            # Compute and Save each round
            X_train = X.iloc[train_index]
            X_test = X.iloc[test_index]
            y_train = y.iloc[train_index, 0]
            y_test = y.iloc[test_index, 0]
            clf.fit(X_train, y_train)
            # Save the model
            fn = os.path.join(config.RESULT_DIRECTORY, experiment, r, f'rf_{fold}')
            pickle.dump(clf, open(fn, 'wb'))
            fold += 1

            y_pred = clf.predict(X_test)

            y_proba = clf.predict_proba(X_test)
            test_y = y_test.apply(lambda x: 1 if x else 0)
            fpr, tpr, thresholds = roc_curve(test_y, y_proba[:, 1])
            tprs.append(np.interp(mean_fpr, fpr, tpr))
            tprs[-1][0] = 0.0
            roc_auc = auc(fpr, tpr)
            aucs.append(roc_auc)
            classification_report(y_test, y_pred)

            # Classification
            current_result = pd.DataFrame(y_test)
            current_result.index.names = ['sample_hash']
            current_result['PredictedLabel'] = y_pred
            current_result = current_result.merge(labels['family'], on='sample_hash', how='left')
            current_result = current_result.rename(columns={'benign': 'TrueLabel'})
            classification_result.append(current_result)

            # Confusion Matrix
            current_cm = pd.crosstab(y_test, y_pred, rownames=['True Value'], colnames=['Predicted Value'],
                                     normalize='index')
            confusion_matrix.append(current_cm)

            # Feature Importance
            current_importance = pd.DataFrame(clf.feature_importances_, index=X_train.columns,
                                              columns=['feat_importance']).sort_values(by='feat_importance',
                                                                                       ascending=False)
            feature_importance.append(current_importance)

            # Classification parameters
            current_report = pd.DataFrame(classification_report(y_test, y_pred, output_dict=True))
            current_report = current_report.swapaxes('index', 'columns')
            current_report = current_report.drop(['accuracy', 'macro avg', 'weighted avg'])
            current_report = current_report.drop(['support'], axis=1)
            current_report['accuracy'] = 0.00
            for segment in [True, False]:
                current_report.at[str(segment), 'accuracy'] = current_cm.at[segment, segment]
            current_report.index.names = ['name']
            classification_reports.append(current_report)

        # Save results
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'trueLabel_predictedLabel_list.pickle'),
                  'wb') as w_file:
            pickle.dump(classification_result, w_file)
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'confusionMatrix_list.pickle'),
                  'wb') as w_file:
            pickle.dump(confusion_matrix, w_file)
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'featureImportance_list.pickle'),
                  'wb') as w_file:
            pickle.dump(feature_importance, w_file)
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'tprs.pickle'), 'wb') as w_file:
            pickle.dump(tprs, w_file)
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'aucs.pickle'), 'wb') as w_file:
            pickle.dump(aucs, w_file)
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'classification_reports.pickle'),
                  'wb') as w_file:
            pickle.dump(classification_reports, w_file)


def check_family(d):
    return pd.Series([len(d), len(d[d.PredictedLabel == False])])


def aggregate_results(experiment):
    cm = []
    feature = []
    feature_partial = dict.fromkeys(config.FEAT_ALL.values())
    for k in feature_partial.keys():
        feature_partial[k] = []
    feature_df = pd.DataFrame(0, index=config.FEAT_ALL.values(), columns=['Average MDI score'])
    best_and_worst = []
    packed_result = []
    reports = []
    for r in [str(x) for x in range(5)]:
        # Get confusion matrix
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'confusionMatrix_list.pickle'),
                  'rb') as rFile:
            cm_list = pickle.load(rFile)
            cm.append(reduce(lambda x, y: x.add(y), cm_list) / len(cm_list))

        # #Get Feature importance
        # with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'featureImportance_list.pickle'),'rb') as rFile:
        #     currentFeatureDF = feature_df.copy()
        #     featList = pickle.load(rFile)
        #     featList = pd.concat(featList,axis=1).mean(axis=1)
        #     for p,v in config.FEAT_PREFIX.items():
        #         temp = featList.loc[[x for x in featList.index if x.startswith(p)]]
        #         feature_partial[v].append(temp)
        #         featList = featList.loc[~featList.index.isin(temp.index)]
        #         currentFeatureDF.loc[v] = temp.sum()
        #     #Check DLLs
        #     feature_partial['dlls'].append(featList)
        #     currentFeatureDF.loc['dlls'] = featList.sum()
        #     feature.append(currentFeatureDF)

        # Who's always bad
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'trueLabel_predictedLabel_list.pickle'),
                  'rb') as rFile:
            results = pickle.load(rFile)
            for result in results:
                result = result[result.family != '']
                grouped = result.groupby('family').apply(check_family)
                grouped = grouped.rename(columns={0: 'numPredicted', 1: 'correctPredictions'})
                best_and_worst.append(grouped)

        # Classification report
        with open(os.path.join(config.RESULT_DIRECTORY, experiment + "/" + r, 'classificationReports.pickle'),
                  'rb') as rFile:
            report_list = pickle.load(rFile)
            reports.append(reduce(lambda x, y: x.add(y), report_list) / len(report_list))

    cm = reduce(lambda x, y: x.add(y), cm) / 5
    # feature = pd.concat(feature,axis=1).mean(axis=1)
    # print(feature)
    # for k,v in feature_partial.items():
    #     concatenation = pd.concat(v,axis=1)
    #     concatenation.index.names = [f'{k} feature']
    #     concatenation = concatenation.rename(columns={k:f'Bootstrap_{k} Avg MDI Score' for k in concatenation.columns})
    #     concatenation = concatenation.fillna(0.0)
    #     concatenation['s'] = concatenation.sum(axis=1)
    #     concatenation = concatenation.sort_values(by='s',ascending=False).head(100).drop('s',axis=1)
    #     concatenation.to_csv(os.path.join(config.RESULT_DIRECTORY,experiment,f'{k}_featureImportance_top100.tsv'),sep='\t')

    best_and_worst = reduce(lambda x, y: x.add(y), best_and_worst)
    best_and_worst['correct'] = 100 * best_and_worst['correctPredictions'] / best_and_worst['numPredicted']
    best_and_worst = best_and_worst.sort_values(by='correct', ascending=True)

    # Load some other infos
    classes_families = pd.read_csv('../features_Yufei/classes.sorted', sep='\t', index_col='family')
    packed = pd.read_csv(os.path.join(config.DATASET_DIRECTORY, 'packed.csv'))
    packed = packed.set_index('SHA256')
    packed = packed.groupby('FAMILY').agg(lambda x: len(x[~x.isna()]) / len(x)).sort_values(by='PACKER/PROTECTOR',
                                                                                            ascending=False)
    all_results = best_and_worst.reset_index().merge(classes_families['class'], left_on='family', right_on='family')
    all_results = all_results[['family', 'correct', 'class']]
    all_results = all_results.merge(packed['PACKER/PROTECTOR'], left_on='family', right_on='FAMILY')
    print(
        f"Correlation between correct predictions and packing is {np.corrcoef(all_results['correct'], all_results['PACKER/PROTECTOR'])}")
    all_results = all_results.set_index('family')
    all_results.index.names = ['Family']
    all_results = all_results.rename(
        columns={'correct': 'Avg Accuracy', 'class': 'Class', 'PACKER/PROTECTOR': '% packed'})
    all_results = all_results[['Class', 'Avg Accuracy', '% packed']]
    all_results['Avg Accuracy'] = round(all_results['Avg Accuracy'] / 100, 3)
    all_results['% packed'] = round(100 * all_results['% packed'], 0)
    all_results = all_results.sort_values(by='Avg Accuracy')
    # Group
    grouped = all_results.groupby('Class').agg('mean')['Avg Accuracy']
    grouped.to_latex(os.path.join(config.RESULT_DIRECTORY, experiment, 'tbl_binary_bestAndWorst_grouped_static.tex'))

    all_results.to_latex(os.path.join(config.RESULT_DIRECTORY, experiment, 'tblar_binary_bestAndWorst.tex'))

    reports = reduce(lambda x, y: x.add(y), reports) / 5
    import IPython
    IPython.embed(colors='Linux')
    reports.to_latex(os.path.join(config.RESULT_DIRECTORY, experiment, 'tblar_binary_report.tex'))
