"""Ingeniería de variables del modelo. Se importa desde el notebook y desde el despliegue."""
import pandas as pd

RAW_COLUMNS = ["cvss", "vector", "complexity", "auth", "cwe", "vendor"]   # columnas crudas que recibe el pipeline
NUM_FEATURES = ["cvss", "cvss_missing"]
CAT_FEATURES = ["vector", "complexity", "auth", "cwe", "vendor", "vcombo"]


def add_features(X, use_epss=False):
    X = X.copy()
    for c in ["vector", "complexity", "auth", "cwe", "vendor"]:
        X[c] = X[c].astype("object").where(X[c].notna(), "missing").astype(str).str.strip().str.upper()
    X["cvss"] = pd.to_numeric(X["cvss"], errors="coerce")
    X["cvss_missing"] = X["cvss"].isna().astype(int)
    X["vcombo"] = X["vector"] + "|" + X["auth"] + "|" + X["complexity"]
    cols = NUM_FEATURES + CAT_FEATURES
    if use_epss:
        X["epss"] = pd.to_numeric(X["epss"], errors="coerce")
        cols = ["epss"] + cols
    return X[cols]
