import os
import pickle
from collections import Counter

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import config

prefix = {
    'generic_': 'generic',
    'pesection': 'sections',
    'header_': 'header',
    'str_': 'strings',
    'imp_': 'imports',
    'ngram_': 'ngrams',
    'opcode_': 'opcodes'
}

suffix = {'dll': 'dlls'}


def classify(binary, experiment):
    # #We don't need this in the binary problem
    # if binary:
    #     return
    # print("One vs Rest classifier")
    # full = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY,experiment,'dataset.pickle'))
    # labels = pd.read_pickle(os.path.join(config.DATASET_DIRECTORY,experiment,'labels.pickle'))
    # labels.index.names = ['sample_hash']
    # full = full.merge(labels['family'],on='sample_hash',how='left')
    # families = set(full.family)

    # Plots
    cValue = list(prefix.values()) + list(suffix.values())
    # columns = cValue.copy()
    # columns.append('family')
    # plot = pd.DataFrame(columns=columns)

    # for index,family in tqdm(enumerate(families),total=len(families)):
    #     plot.at[index,'family'] = family
    #     current = full[full.family==family]
    #     howMany = max(round(len(current)/(len(families)-1)),1)
    #     others = full[full.family!=family].groupby('family').sample(n=howMany)
    #     current = pd.concat([current,others.sample(min(len(current),len(others)))])

    #     X = current.drop(['ms_elapsed','family'],axis=1)
    #     y = current['family'].apply(lambda x: True if x==family else False)

    #     X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    #     clf = RandomForestClassifier(
    #             n_jobs=config.CORES, 
    #             max_depth = 20,
    #             n_estimators = 225, 
    #             max_features='sqrt')

    #     clf.fit(X_train, y_train)
    #     y_pred = clf.predict(X_test)
    #     accuracy = accuracy_score(y_test, y_pred)
    #     # print("\t{} - {} - {} - {}".format(index,family,len(current),accuracy))

    #     #Feature Importance
    #     currentImportance = pd.DataFrame(clf.feature_importances_,index=X_train.columns,columns=['feat_importance']).sort_values(by='feat_importance',ascending=False)
    #     currentBig = 0
    #     for p in prefix.keys():
    #         temp = currentImportance.loc[[x for x in currentImportance.index if x.startswith(p)]]
    #         currentImportance = currentImportance.loc[~currentImportance.index.isin(temp.index)]
    #         plot.at[index,prefix[p]] = temp.sum().values[0]
    #     #Check Dll
    #     plot.at[index,'dlls'] = currentImportance.sum().values[0]

    # plot.to_pickle(os.path.join(config.RESULT_DIRECTORY,experiment,'oneVsRestImportance.pickle'))
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, 'oneVsRestImportance.pickle'), 'rb') as rFile:
        plot = pickle.load(rFile)

    import IPython
    IPython.embed(colors='Linux')
    plotDict = dict()
    for fClass in config.FEAT_ALL.values():
        plotDict[fClass] = list(plot[fClass].values)

    fig, ax = plt.subplots()
    ax.boxplot(plotDict.values())
    ax.set_xticklabels([x.capitalize() for x in plotDict.keys()])
    ax.set_xlabel('Feature class', fontsize=13, labelpad=10)
    ax.set_ylabel('MDI average importance', rotation=90, fontsize=13, labelpad=10)
    fig.tight_layout()
    fig.savefig(os.path.join(config.PLOTS_DIRECTORY, experiment, 'oneVsRest_featureImportanceBoxplot.pdf'))

    plot[cValue] = plot[cValue].astype(float)
    topFeature = plot[cValue].idxmax(axis=1)
    plot['topFeature'] = topFeature
    sorter = [x for x, y in Counter(topFeature).most_common()]
    lines = [x - 1 for x in np.cumsum([y for x, y in Counter(topFeature).most_common()])]
    plot['topFeature'] = plot['topFeature'].astype("category")
    plot['topFeature'].cat.set_categories(sorter, inplace=True)
    plot = plot.sort_values(by='topFeature')
    sortingPieces = []
    for c in sorter:
        sortingPieces.append(plot[plot.topFeature == c].sort_values(by=c, ascending=False))
    plot = pd.concat(sortingPieces)
    plot['x'] = range(0, len(plot))

    # PLOT
    fig, ax = plt.subplots()
    previous = [0] * len(plot)
    curves = sorter.copy()
    curves.extend([x for x in cValue if x not in sorter])
    for curve in curves:
        current = [x + y for x, y in zip(previous, plot[curve])]
        ax.fill_between(plot['x'], previous, current, label=curve)
        previous = current.copy()
    ax.tick_params(
        axis='x',
        which='both',
        bottom=False,
        top=False,
        labelbottom=False)
    # Lines
    for i, l in enumerate(lines):
        if l != max(plot.x):
            ax.vlines(l, 0, 1, colors='k', linestyles='-.')
        x = l / 2 if i == 0 else lines[i - 1] + (l - lines[i - 1]) / 2
        ax.text(x, 1.03, sorter[i], horizontalalignment='left', rotation=45)
    ax.set_xlabel('Families')
    ax.set_ylabel('Feature Importance')
    ax.spines['right'].set_visible(False)
    ax.spines['top'].set_visible(False)
    lgd = ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.28), ncol=4)

    # Save all
    fig.subplots_adjust(right=1.1)
    fig.savefig(
        os.path.join(config.PLOTS_DIRECTORY, experiment, 'featureImportance_{}_OneVsRest.pdf'.format(experiment)),
        bbox_extra_artists=(lgd,), bbox_inches='tight')
    with open(os.path.join(config.RESULT_DIRECTORY, experiment, 'oneVsRestImportance.pickle'), 'wb') as wFile:
        pickle.dump(plot, wFile)
