import pandas as pd
import numpy as np


def print_statistics(df: pd.DataFrame, split: pd.Timestamp, label: str = ""):
    df_train, df_test = df[df["first_submission_date"] < split], df[df["first_submission_date"] >= split]
    print("------------------------------------------------------------------")
    print(f"Report: {label}")
    print(f"\tTraining set length: {len(df_train)}, ({round(len(df_train) / len(df) * 100, 2)}%)")
    print(f"\tTesting set length: {len(df_test)}, ({round(len(df_test) / len(df) * 100, 2)}%)")
    print(f"\tNum families in training: {len(df_train['family'].unique())}")
    print(f"\tNum families in testing: {len(df_test['family'].unique())}")

    n_cup = len(np.intersect1d(df_train['family'].unique(), df_test['family'].unique()))
    print(f"\tCommon families: {n_cup}")
    n_new_families = len(df_test['family'].unique()) - n_cup
    n_dis_families = len(df_train['family'].unique()) - n_cup
    print(f"\tFamilies in training but not in testing: {n_dis_families} "
          f"({round(n_dis_families / len(df['family'].unique()) * 100, 2)}%)")
    print(f"\tFamilies in testing but not in training: {n_new_families} "
          f"({round(n_new_families / len(df['family'].unique()) * 100, 2)}%)")


def split_and_group_nonzero(src_df: pd.DataFrame, split_condition: bool):
    """
    1. Split the source dataframe by the split_condition
    2. Group by the samples by family by creating a "count" column with the size of each group
    """
    dst_df = src_df.copy()
    dst_df = dst_df[split_condition]
    dst_df = dst_df.groupby(["family"]).size().reset_index(name='count')
    return dst_df


def split_and_group(src_df: pd.DataFrame, split_condition: bool,
                    ref_df: pd.DataFrame):
    """
    Given a source dataset with the following columns: [family, count],
    extend it by adding families of reference dataframe not yet included, setting counts to zeros.
    """
    df = split_and_group_nonzero(src_df=src_df, split_condition=split_condition)
    missed_families = [f for f in ref_df["family"].unique() if f not in list(df["family"])]
    df_missed_families = pd.DataFrame({"family": missed_families, "count": np.zeros(len(missed_families))})
    dst_df = pd.concat([df, df_missed_families]).sort_values(by="family")
    return dst_df
