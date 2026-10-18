"""Loads the unified URL dataset and makes the time-based train/test split."""
import pandas as pd

from phishstream.config import EVENTS_CSV

TEST_DAYS = 20


def load(path=EVENTS_CSV) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df["label"] = df["label"].astype(int)
    df["first_seen"] = pd.to_datetime(df["first_seen"], errors="coerce")
    return df.dropna(subset=["first_seen"]).reset_index(drop=True)


def time_split(df: pd.DataFrame, test_days: int = TEST_DAYS):
    """Train on the past, test on the future: new campaigns in the test window were never seen
    in training, which is how a deployed detector is actually used (no leakage)."""
    cutoff = df["first_seen"].max() - pd.Timedelta(days=test_days)
    return df[df["first_seen"] <= cutoff], df[df["first_seen"] > cutoff], cutoff
