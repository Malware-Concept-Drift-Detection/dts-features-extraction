from typing import Callable

import pandas as pd
import numpy as np
from scipy.spatial.distance import jensenshannon


fsd = "first_submission_date"


def print_statistics(df: pd.DataFrame, split: pd.Timestamp, label: str = ""):
    df_train, df_test = df[df[fsd] < split], df[df[fsd] >= split]
    print("------------------------------------------------------------------")
    print(f"Report: {label}")
    print(
        f"\tTraining set length: {len(df_train)}, ({round(len(df_train) / len(df) * 100, 2)}%)"
    )
    print(
        f"\tTesting set length: {len(df_test)}, ({round(len(df_test) / len(df) * 100, 2)}%)"
    )
    print(f"\tNum families in training: {len(df_train['family'].unique())}")
    print(f"\tNum families in testing: {len(df_test['family'].unique())}")

    n_cup = len(np.intersect1d(df_train["family"].unique(), df_test["family"].unique()))
    print(f"\tCommon families: {n_cup}")
    n_new_families = len(df_test["family"].unique()) - n_cup
    n_dis_families = len(df_train["family"].unique()) - n_cup
    print(
        f"\tFamilies in training but not in testing: {n_dis_families} "
        f"({round(n_dis_families / len(df['family'].unique()) * 100, 2)}%)"
    )
    print(
        f"\tFamilies in testing but not in training: {n_new_families} "
        f"({round(n_new_families / len(df['family'].unique()) * 100, 2)}%)"
    )


def split_and_group_nonzero(src_df: pd.DataFrame, split_condition: bool):
    """
    1. Split the source dataframe by the split_condition
    2. Group by the samples by family by creating a "count" column with the size of each group
    """
    dst_df = src_df.copy()
    dst_df = dst_df[split_condition]
    dst_df = dst_df.groupby(["family"]).size().reset_index(name="count")
    return dst_df


def split_and_group(src_df: pd.DataFrame, split_condition: bool, ref_df: pd.DataFrame):
    """
    Given a source dataset with the following columns: [family, count],
    extend it by adding families of reference dataframe not yet included, setting counts to zeros.
    """
    df = split_and_group_nonzero(src_df=src_df, split_condition=split_condition)
    missed_families = [
        f for f in ref_df["family"].unique() if f not in list(df["family"])
    ]
    df_missed_families = pd.DataFrame(
        {"family": missed_families, "count": np.zeros(len(missed_families))}
    )
    dst_df = pd.concat([df, df_missed_families]).sort_values(by="family")
    return dst_df


def compute_scores(
    df: pd.DataFrame,
    ref_df: pd.DataFrame,
    date_split: pd.Timestamp,
    bs_f: Callable = lambda x: 1 - np.abs(x - 0.8) / 0.8,
):
    """
    Compute the scores given a dataset and a timestamp as data split:
    Jensen-Shannon score, Train-Test balancing, % Appearing families in testing set
    """
    # JS
    df_train_all = split_and_group(
        src_df=df, split_condition=df[fsd] < date_split, ref_df=ref_df
    )
    df_test_all = split_and_group(
        src_df=df, split_condition=df[fsd] >= date_split, ref_df=ref_df
    )
    js = jensenshannon(np.array(df_train_all["count"]), np.array(df_test_all["count"]))

    # Train-Test balancing: this score increases as the training test length
    # in % is approaching 80% of the samples
    train_prop = len(df[df[fsd] < date_split]) / len(ref_df)
    bs = bs_f(train_prop)

    # % Appearing families in testing set
    df_train_nonzero = split_and_group_nonzero(
        src_df=df, split_condition=df[fsd] < date_split
    )
    df_test_nonzero = split_and_group_nonzero(
        src_df=df, split_condition=df[fsd] >= date_split
    )

    test_families = df_test_nonzero["family"].unique()
    af = (
        len(test_families)
        - len(np.intersect1d(df_train_nonzero["family"].unique(), test_families))
    ) / len(ref_df["family"].unique())

    return {"js": js, "bs": bs, "af": af}
