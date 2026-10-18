# Construye la tabla de CVEs unida con KEV y EPSS
import json
from pathlib import Path
import pandas as pd

CARPETA_CVES = Path("data/cvelistV5/cves")
FICHERO_KEV = "data/kev.csv"
FICHERO_EPSS = "data/epss.csv.gz"
ANIO_MINIMO = 2021

# orden de preferencia de las versiones de CVSS
VERSIONES = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


def sacar_cvss(contenedores):
    # busca el CVSS en el contenedor del CNA y en los ADP
    encontrados = {}
    lista = [contenedores.get("cna", {})] + contenedores.get("adp", [])
    for c in lista:
        for metrica in c.get("metrics", []):
            for version, datos in metrica.items():
                if version.startswith("cvssV") and "baseScore" in datos:
                    encontrados.setdefault(version, datos)
    for version in VERSIONES:
        if version in encontrados:
            d = encontrados[version]
            return d["baseScore"], d.get("vectorString"), version
    return None, None, None


def leer_cve(ruta):
    with open(ruta, encoding="utf-8") as f:
        datos = json.load(f)

    meta = datos["cveMetadata"]
    if meta.get("state") != "PUBLISHED":
        return None  # descarto los rechazados

    cna = datos["containers"].get("cna", {})
    afectado = (cna.get("affected") or [{}])[0]

    cwe = None
    for tipo in cna.get("problemTypes", []):
        for desc in tipo.get("descriptions", []):
            if desc.get("cweId"):
                cwe = desc["cweId"]
                break

    score, vector, version = sacar_cvss(datos["containers"])
    return {
        "cveID": meta["cveId"],
        "published": meta.get("datePublished"),
        "vendor": afectado.get("vendor"),
        "product": afectado.get("product"),
        "cwe": cwe,
        "cvss": score,
        "cvss_vector": vector,
        "cvss_version": version,
    }


filas = []
for ruta in CARPETA_CVES.rglob("CVE-*.json"):
    anio = int(ruta.parent.parent.name)  # carpeta del año de asignación
    if anio < ANIO_MINIMO:
        continue
    fila = leer_cve(ruta)
    if fila:
        filas.append(fila)

cve = pd.DataFrame(filas)
cve["published"] = pd.to_datetime(cve["published"], utc=True, format="ISO8601")

kev = pd.read_csv(FICHERO_KEV)
kev["dateAdded"] = pd.to_datetime(kev["dateAdded"], utc=True)

# la primera línea del EPSS es un comentario con la versión del modelo
epss = pd.read_csv(FICHERO_EPSS, comment="#").rename(columns={"cve": "cveID"})

df = cve.merge(kev[["cveID", "dateAdded", "knownRansomwareCampaignUse"]], on="cveID", how="left")
df = df.merge(epss, on="cveID", how="left")
df["en_KEV"] = df["dateAdded"].notna().astype(int)
df["dias_hasta_KEV"] = (df["dateAdded"] - df["published"]).dt.days

df.to_parquet("data/cves_kev_epss.parquet", index=False)

print("=== PARA LA FICHA ===")
print("filas x columnas:", df.shape)
print("MB en memoria:", round(df.memory_usage(deep=True).sum() / 1e6, 1))
print("publicados:", df["published"].min(), "->", df["published"].max())
print("duplicados cveID:", df["cveID"].duplicated().sum())
print("en_KEV:", df["en_KEV"].sum(), f"({df['en_KEV'].mean():.2%})")
print("KEV fuera de la tabla:", (~kev["cveID"].isin(df["cveID"])).sum())
print("\nNulos (%):")
print((df[["vendor", "product", "cwe", "cvss", "cvss_vector", "epss"]].isna().mean() * 100).round(1))
print("\nVersion CVSS:\n", df["cvss_version"].value_counts(dropna=False))
print("\nVendors distintos:", df["vendor"].nunique())
