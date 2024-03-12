#!/usr/bin/env python3
from tqdm import tqdm
import config
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_curve, auc, classification_report
from collections import Counter, OrderedDict
from sklearn import model_selection
import pickle
import math
import random
import seaborn as sns
import matplotlib.pyplot as plt
import multiprocessing as mp
from functools import partial,reduce

def classify(experiment,plot):

    for r in [str(x) for x in range(5)]:
        print(f"Loading dataset and labels. Round {r}")
        full = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY,experiment+'/'+r,'dataset.pickle'))
        try:
            full = full.drop('pesectionProcessed_entrypointSection_name',axis=1)
        except:
            pass
        labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY,experiment+'/'+r,'labels.pickle'))
        labels.index.names = ['sample_hash']
        full = full.merge(labels[['benign','family','set']],on='sample_hash',how='left')
        X = full.drop(['ms_elapsed','set','family','benign'],axis=1)
        y = full[['benign','family']]
        #This is only for packed only binary
        y['family'] = y['family'].apply(lambda x: 'malware' if x else 'goodware')
        #This is only for packed only binary

        print("Training the classifier")
        clf = RandomForestClassifier(
            n_jobs=config.CORES, 
            max_depth = None,
            n_estimators = 225, 
            max_features='sqrt')

        classificationResult = []
        classificationReports = []
        confusion_matrix = []
        feature_importance = []
        tprs = []
        aucs = []
        mean_fpr = np.linspace(0, 1, 100)

        n_splits=10
        kfold = model_selection.StratifiedShuffleSplit(n_splits=n_splits, test_size=.2)

        fold = 0
        for train_index, test_index in tqdm(kfold.split(X,y),total=n_splits):

            #Compute and Save each round
            X_train = X.iloc[train_index]
            X_test = X.iloc[test_index]
            y_train = y.iloc[train_index,0]
            y_test = y.iloc[test_index,0]
            clf.fit(X_train, y_train)
            #Save the model
            fn = os.path.join(config.RESULT_DIRECTORY,experiment,r,f'rf_{fold}')
            pickle.dump(clf, open(fn, 'wb'))
            fold+=1

            y_pred = clf.predict(X_test)

            y_proba = clf.predict_proba(X_test)
            test_y = y_test.apply(lambda x: 1 if x else 0)
            fpr, tpr, thresholds = roc_curve(test_y, y_proba[:, 1])
            tprs.append(np.interp(mean_fpr, fpr, tpr))
            tprs[-1][0] = 0.0
            roc_auc = auc(fpr, tpr)
            aucs.append(roc_auc)
            classification_report(y_test, y_pred)

            #Classification
            currentResult = pd.DataFrame(y_test)
            currentResult.index.names = ['sample_hash']
            currentResult['PredictedLabel'] = y_pred
            currentResult = currentResult.merge(labels['family'], on='sample_hash',how='left')
            currentResult = currentResult.rename(columns={'benign':'TrueLabel'})
            classificationResult.append(currentResult)

            #Confusion Matrix
            currentCM = pd.crosstab(y_test, y_pred, rownames=['True Value'], colnames=['Predicted Value'],normalize='index')
            confusion_matrix.append(currentCM)

            #Feature Importance
            currentImportance = pd.DataFrame(clf.feature_importances_,index=X_train.columns,columns=['feat_importance']).sort_values(by='feat_importance',ascending=False)
            feature_importance.append(currentImportance)

            #Classification parameters
            currentReport = pd.DataFrame(classification_report(y_test,y_pred,output_dict=True))
            currentReport = currentReport.swapaxes('index','columns')
            currentReport = currentReport.drop(['accuracy','macro avg','weighted avg'])
            currentReport = currentReport.drop(['support'],axis=1)
            currentReport['accuracy'] = 0.00
            for segment in [True,False]:
                currentReport.at[str(segment),'accuracy'] = currentCM.at[segment,segment]
            currentReport.index.names = ['name']
            classificationReports.append(currentReport)

        #Save results
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'trueLabel_predictedLabel_list.pickle'),'wb') as wFile:
            pickle.dump(classificationResult,wFile)
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'confusionMatrix_list.pickle'),'wb') as wFile:
            pickle.dump(confusion_matrix,wFile)
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'featureImportance_list.pickle'),'wb') as wFile:
            pickle.dump(feature_importance,wFile)
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'tprs.pickle'),'wb') as wFile:
            pickle.dump(tprs,wFile)
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'aucs.pickle'),'wb') as wFile:
            pickle.dump(aucs,wFile)
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'classificationReports.pickle'),'wb') as wFile:
            pickle.dump(classificationReports,wFile)

def checkFamily(d):
    return pd.Series([len(d), len(d[d.PredictedLabel==False])])

def aggregateResults(experiment):
    cm = []
    feature = []
    featurePartial = dict.fromkeys(config.FEAT_ALL.values())
    for k in featurePartial.keys():
        featurePartial[k] = []
    featureDF = pd.DataFrame(0,index=config.FEAT_ALL.values(),columns=['Average MDI score'])
    bestAndWorst = []
    packedResult = []
    reports = []
    for r in [str(x) for x in range(5)]:
        #Get confusion matrix
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'confusionMatrix_list.pickle'),'rb') as rFile:
            cmList = pickle.load(rFile)
            cm.append(reduce(lambda x, y: x.add(y), cmList)/len(cmList))

        # #Get Feature importance
        # with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'featureImportance_list.pickle'),'rb') as rFile:
        #     currentFeatureDF = featureDF.copy()
        #     featList = pickle.load(rFile)
        #     featList = pd.concat(featList,axis=1).mean(axis=1)
        #     for p,v in config.FEAT_PREFIX.items():
        #         temp = featList.loc[[x for x in featList.index if x.startswith(p)]]
        #         featurePartial[v].append(temp)
        #         featList = featList.loc[~featList.index.isin(temp.index)]
        #         currentFeatureDF.loc[v] = temp.sum()
        #     #Check DLLs
        #     featurePartial['dlls'].append(featList)
        #     currentFeatureDF.loc['dlls'] = featList.sum()
        #     feature.append(currentFeatureDF)

        #Who's always bad
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'trueLabel_predictedLabel_list.pickle'),'rb') as rFile:
            results = pickle.load(rFile)
            for result in results:
                result = result[result.family!='']
                grouped = result.groupby('family').apply(checkFamily)
                grouped = grouped.rename(columns={0:'numPredicted',1:'correctPredictions'})
                bestAndWorst.append(grouped)

        # Classification report
        with open(os.path.join(config.RESULT_DIRECTORY,experiment+"/"+r,'classificationReports.pickle'),'rb') as rFile:
            reportList = pickle.load(rFile)
            reports.append(reduce(lambda x, y: x.add(y), reportList)/len(reportList))

    cm = reduce(lambda x, y: x.add(y), cm)/5
    # feature = pd.concat(feature,axis=1).mean(axis=1)
    # print(feature)
    # for k,v in featurePartial.items():
    #     concatenation = pd.concat(v,axis=1)
    #     concatenation.index.names = [f'{k} feature']
    #     concatenation = concatenation.rename(columns={k:f'Bootstrap_{k} Avg MDI Score' for k in concatenation.columns})
    #     concatenation = concatenation.fillna(0.0)
    #     concatenation['s'] = concatenation.sum(axis=1)
    #     concatenation = concatenation.sort_values(by='s',ascending=False).head(100).drop('s',axis=1)
    #     concatenation.to_csv(os.path.join(config.RESULT_DIRECTORY,experiment,f'{k}_featureImportance_top100.tsv'),sep='\t')

    bestAndWorst = reduce(lambda x, y: x.add(y), bestAndWorst)
    bestAndWorst['correct'] = 100*bestAndWorst['correctPredictions']/bestAndWorst['numPredicted']
    bestAndWorst = bestAndWorst.sort_values(by='correct',ascending=True)

    #Load some other infos
    classesFamilies = pd.read_csv('../features_Yufei/classes.sorted',sep='\t',index_col='family')
    packed = pd.read_csv(os.path.join(config.DATASET_DIRECTORY,'packed.csv'))
    packed = packed.set_index('SHA256')
    packed = packed.groupby('FAMILY').agg(lambda x: len(x[~x.isna()])/len(x)).sort_values(by='PACKER/PROTECTOR',ascending=False)
    allResults = bestAndWorst.reset_index().merge(classesFamilies['class'],left_on='family',right_on='family')
    allResults = allResults[['family','correct','class']]
    allResults = allResults.merge(packed['PACKER/PROTECTOR'],left_on='family',right_on='FAMILY')
    print(f"Correlation between correct predictions and packing is {np.corrcoef(allResults['correct'],allResults['PACKER/PROTECTOR'])}")
    allResults = allResults.set_index('family')
    allResults.index.names = ['Family']
    allResults = allResults.rename(columns={'correct':'Avg Accuracy','class':'Class','PACKER/PROTECTOR':'% packed'})
    allResults = allResults[['Class','Avg Accuracy','% packed']]
    allResults['Avg Accuracy'] = round(allResults['Avg Accuracy']/100,3)
    allResults['% packed'] = round(100*allResults['% packed'],0)
    allResults = allResults.sort_values(by='Avg Accuracy')
    #Group
    grouped = allResults.groupby('Class').agg('mean')['Avg Accuracy']
    grouped.to_latex(os.path.join(config.RESULT_DIRECTORY,experiment,'tbl_binary_bestAndWorst_grouped_static.tex'))

    allResults.to_latex(os.path.join(config.RESULT_DIRECTORY,experiment,'tblar_binary_bestAndWorst.tex'))

    reports = reduce(lambda x, y: x.add(y), reports)/5
    import IPython; IPython.embed(colors='Linux')
    reports.to_latex(os.path.join(config.RESULT_DIRECTORY,experiment,'tblar_binary_report.tex'))
