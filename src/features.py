from __future__ import annotations
import numpy as np
import pandas as pd

FEATURES = ["packet_rate","avg_size","unique_ports","syn_ratio"]

def _num(df, name, default=0.0):
    if name not in df.columns:
        return pd.Series(default, index=df.index, dtype="float64")
    return pd.to_numeric(df[name], errors="coerce").replace([np.inf,-np.inf],np.nan).fillna(default)

def normalize_columns(df):
    df=df.copy()
    df.columns=[str(c).strip() for c in df.columns]
    return df

def dataset_to_features(df):
    df=normalize_columns(df)
    duration=_num(df,"Flow Duration",1.0).clip(lower=1)
    pkts=(_num(df,"Total Fwd Packets")+_num(df,"Total Backward Packets")).clip(lower=1)
    bytes_=(_num(df,"Total Length of Fwd Packets")+_num(df,"Total Length of Bwd Packets")).clip(lower=0)
    rate=pkts/(duration/1_000_000.0)
    avg=bytes_/pkts
    ports=_num(df,"Destination Port").clip(0,65535)
    syn=(_num(df,"SYN Flag Count")/pkts).clip(0,1)
    out=pd.DataFrame({
        "packet_rate":np.log1p(rate.clip(0,100000)),
        "avg_size":np.log1p(avg.clip(0,100000)),
        "unique_ports":np.log1p(ports),
        "syn_ratio":syn
    })
    return out.replace([np.inf,-np.inf],np.nan).fillna(0)

def live_features(packets, window_seconds=5.0):
    if not packets:
        return {"packet_rate":0.0,"avg_size":0.0,"unique_ports":0.0,"syn_ratio":0.0,
                "packet_rate_raw":0.0,"avg_size_raw":0.0,"unique_ports_raw":0}
    elapsed=max(packets[-1]["time"]-packets[0]["time"],0.001)
    rate=len(packets)/max(elapsed,window_seconds)
    avg=sum(p["size"] for p in packets)/len(packets)
    ports={p.get("dst_port") for p in packets if p.get("dst_port") is not None}
    syn=sum(1 for p in packets if p.get("syn"))
    return {"packet_rate":float(np.log1p(min(rate,100000))),
            "avg_size":float(np.log1p(min(avg,100000))),
            "unique_ports":float(np.log1p(min(len(ports),65535))),
            "syn_ratio":float(min(max(syn/len(packets),0),1)),
            "packet_rate_raw":float(rate),"avg_size_raw":float(avg),
            "unique_ports_raw":int(len(ports))}
