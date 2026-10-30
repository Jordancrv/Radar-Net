from dataclasses import dataclass
from pathlib import Path
import joblib

@dataclass
class Decision:
    attack:str; severity:str; confidence:int; source:str; action:str; reason:str

class HybridEngine:
    def __init__(self):
        base=Path(__file__).resolve().parent.parent
        p=base/"models"/"cyberguardian_rf.joblib"
        self.model=joblib.load(p) if p.exists() else None
        from rules import RuleEngine
        self.rules=RuleEngine()
    @property
    def model_ready(self): return self.model is not None
    def analyze(self,t):
        out=[]
        for a in self.rules.evaluate(t["packet_rate_raw"],int(t["unique_ports_raw"]),
                                     int(t.get("failed_logins",0)),t["syn_ratio"]):
            out.append(Decision(a["type"],a["severity"],a["confidence"],"REGLAS",
                                "RESPUESTA SIMULADA",a["reason"]))
        if self.model:
            x=[[t["packet_rate"],t["avg_size"],t["unique_ports"],t["syn_ratio"]]]
            pred=int(self.model.predict(x)[0]); prob=float(self.model.predict_proba(x)[0][1])
            if pred==1 and prob>=0.70:
                out.append(Decision("ATAQUE DETECTADO","CRITICO" if prob>=.90 else "ALTO",
                                    int(prob*100),"MACHINE LEARNING","AISLAR EQUIPO (SIMULADO)",
                                    f"Probabilidad estimada de ataque: {prob:.2%}."))
        rules=[x for x in out if x.source=="REGLAS"]; ml=[x for x in out if x.source=="MACHINE LEARNING"]
        if rules and ml:
            r=rules[0]; m=ml[0]
            out.append(Decision("CORROBORADO: "+r.attack,"CRITICO",
                                min(99,max(r.confidence,m.confidence)+3),"HIBRIDO",
                                "RESPUESTA PRIORITARIA (SIMULADA)",
                                "Reglas y Machine Learning coinciden."))
        return list({x.attack:x for x in out}.values())
