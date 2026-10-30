from pathlib import Path
import sys,json
import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,classification_report,confusion_matrix
from sklearn.model_selection import train_test_split
sys.path.append(str(Path(__file__).resolve().parent))
from features import dataset_to_features

BASE=Path(__file__).resolve().parent.parent
DATA=BASE/"data"/"cicids2017"; MODELS=BASE/"models"; REPORTS=BASE/"reports"

def load():
    csvs=list(DATA.glob("*.csv"))
    if not csvs: raise FileNotFoundError("No hay CSV en data/cicids2017.")
    frames=[]
    for f in csvs:
        print("Cargando:",f.name)
        df=pd.read_csv(f,low_memory=False); lab=next((c for c in df.columns if str(c).strip().lower()=="label"),None)
        if lab is None: raise ValueError(f"No se encontro Label en {f.name}")
        df=df.rename(columns={lab:"Label"}); frames.append(df)
    d=pd.concat(frames,ignore_index=True)
    d["Label"]=d["Label"].astype(str).str.strip()
    d["target"]=(d["Label"].str.upper()!="BENIGN").astype(int)
    return d

d=load(); print("Filas:",len(d))
X=dataset_to_features(d); y=d.target
z=X.copy(); z["target"]=y.to_numpy(); z=z.drop_duplicates()
X=z.drop(columns="target"); y=z.target
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
model=RandomForestClassifier(n_estimators=250,max_depth=18,min_samples_leaf=2,
    class_weight="balanced_subsample",n_jobs=-1,random_state=42)
model.fit(Xtr,ytr); p=model.predict(Xte)
m={"dataset_rows_after_dedup":int(len(X)),"train_rows":int(len(Xtr)),"test_rows":int(len(Xte)),
   "accuracy":float(accuracy_score(yte,p)),"precision":float(precision_score(yte,p,zero_division=0)),
   "recall":float(recall_score(yte,p,zero_division=0)),"f1":float(f1_score(yte,p,zero_division=0)),
   "features":list(X.columns)}
MODELS.mkdir(exist_ok=True); REPORTS.mkdir(exist_ok=True)
joblib.dump(model,MODELS/"cyberguardian_rf.joblib")
(REPORTS/"metrics.json").write_text(json.dumps(m,indent=2),encoding="utf-8")
(REPORTS/"classification_report.txt").write_text(classification_report(yte,p,target_names=["BENIGN","ATTACK"],zero_division=0),encoding="utf-8")
cm=confusion_matrix(yte,p,labels=[0,1])
pd.DataFrame(cm,index=["REAL_BENIGN","REAL_ATTACK"],columns=["PRED_BENIGN","PRED_ATTACK"]).to_csv(REPORTS/"confusion_matrix.csv")
plt.figure(figsize=(6,5)); plt.imshow(cm); plt.title("Matriz de Confusion"); plt.xticks([0,1],["BENIGN","ATTACK"]); plt.yticks([0,1],["BENIGN","ATTACK"]); plt.xlabel("Prediccion"); plt.ylabel("Real")
for i in range(2):
    for j in range(2): plt.text(j,i,cm[i,j],ha="center",va="center")
plt.tight_layout(); plt.savefig(REPORTS/"confusion_matrix.png",dpi=150); plt.close()
names=["Accuracy","Precision","Recall","F1"]; vals=[m["accuracy"],m["precision"],m["recall"],m["f1"]]
plt.figure(figsize=(7,4)); plt.bar(names,vals); plt.ylim(0,1); plt.title("Metricas del modelo"); plt.ylabel("Score")
for i,v in enumerate(vals): plt.text(i,min(v+.02,.98),f"{v:.3f}",ha="center")
plt.tight_layout(); plt.savefig(REPORTS/"model_metrics.png",dpi=150); plt.close()
plt.figure(figsize=(6,4)); counts=[int((d.target==0).sum()),int((d.target==1).sum())]; plt.bar(["BENIGN","ATTACK"],counts); plt.title("Distribucion del dataset"); plt.ylabel("Registros"); plt.tight_layout(); plt.savefig(REPORTS/"class_distribution.png",dpi=150); plt.close()
print("\n=== RESULTADOS ===")
for k in ["accuracy","precision","recall","f1"]: print(f"{k.title():9s}: {m[k]:.4f}")
