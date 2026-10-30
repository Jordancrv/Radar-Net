import json,math,random,sys
from pathlib import Path
import tkinter as tk
from tkinter import ttk,messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
sys.path.append(str(Path(__file__).resolve().parent))
from capture import LanCapture
from db import insert_event,summary,recent,timeline_by_attack
from features import live_features
from hybrid_engine import HybridEngine
from graph_search import EDGES,NODES,search
BASE=Path(__file__).resolve().parent.parent

class App:
    def __init__(self,root):
        self.root=root; self.root.title("RadarNET")
        self.ui_scale=max(1.1,min(1.8,min(root.winfo_screenwidth()/1760,root.winfo_screenheight()/1000)))
        self.root.geometry(f"{round(1280*self.ui_scale)}x{round(880*self.ui_scale)}")
        self.setup_styles()
        self.engine=HybridEngine(); self.capture=None; self.total_packets=0; self.session_threats=0; self.session_responses=0
        self.capture_status="DETENIDO"; self.last_capture_packets=0
        self.build(); self.refresh()
    def scaled_font(self,size,weight="normal"):
        return ("Segoe UI",round(size*self.ui_scale),weight)
    def setup_styles(self):
        style=ttk.Style(self.root)
        style.configure(".",font=self.scaled_font(10))
        style.configure("Treeview",font=self.scaled_font(10),rowheight=round(24*self.ui_scale))
        style.configure("Treeview.Heading",font=self.scaled_font(10,"bold"))
        style.configure("TLabelframe.Label",font=self.scaled_font(10,"bold"))
    def build(self):
        f=ttk.Frame(self.root); f.pack(fill="x",padx=20,pady=(15,5))
        ttk.Label(f,text="RADARNET",font=self.scaled_font(24,"bold")).pack(anchor="center")
        ttk.Label(f,text="SOC académico • ML + Reglas + SQLite + Captura LAN").pack()
        s=ttk.Frame(self.root); s.pack(fill="x",padx=20,pady=8)
        self.lp=ttk.Label(s,text="Paquetes: 0",font=self.scaled_font(12,"bold")); self.lp.pack(side="left",padx=12)
        self.lt=ttk.Label(s,text="Amenazas sesión: 0",font=self.scaled_font(12,"bold")); self.lt.pack(side="left",padx=12)
        self.lr=ttk.Label(s,text="Respuestas: 0",font=self.scaled_font(12,"bold")); self.lr.pack(side="left",padx=12)
        self.lm=ttk.Label(s,text="MODELO CARGADO" if self.engine.model_ready else "MODELO NO ENTRENADO",font=self.scaled_font(12,"bold")); self.lm.pack(side="right")
        c=ttk.LabelFrame(self.root,text="Control"); c.pack(fill="x",padx=20,pady=8)
        ttk.Label(c,text="Interfaz Scapy:").grid(row=0,column=0,padx=5,pady=9)
        self.iface=ttk.Combobox(c,width=58,state="readonly"); self.iface.grid(row=0,column=1,columnspan=2,padx=5)
        self.capture_button=ttk.Button(c,text="Activar escaneo",command=self.start); self.capture_button.grid(row=0,column=3,padx=4)
        self.stop_button=ttk.Button(c,text="Desactivar escaneo",command=self.stop,state="disabled"); self.stop_button.grid(row=0,column=4,padx=4)
        ttk.Button(c,text="Actualizar interfaces",command=self.interfaces).grid(row=0,column=5,padx=4)
        ttk.Button(c,text="Simular ataque",command=self.simulate).grid(row=0,column=6,padx=4)
        ttk.Button(c,text="Ver métricas",command=self.metrics).grid(row=0,column=7,padx=4)
        ttk.Button(c,text="Actualizar",command=self.refresh).grid(row=0,column=8,padx=4)
        ttk.Button(c,text="Analizar ruta",command=self.open_graph_search).grid(row=0,column=9,padx=4)
        self.status=ttk.Label(c,text="Estado: DETENIDO | Ventana: 0 paquetes")
        self.status.grid(row=1,column=0,columnspan=9,sticky="w",padx=5,pady=(0,7))
        self.interfaces()
        panels=ttk.PanedWindow(self.root,orient="vertical")
        panels.pack(fill="both",expand=True,padx=20,pady=(8,15))
        tf=ttk.LabelFrame(panels,text="Eventos de seguridad")
        cols=("time","src","dst","attack","sev","conf","engine","action"); self.tree=ttk.Treeview(tf,columns=cols,show="headings")
        heads={"time":"Fecha/Hora","src":"IP origen","dst":"IP destino","attack":"Amenaza","sev":"Nivel","conf":"Confianza","engine":"Motor","action":"Respuesta"}
        widths={"time":145,"src":120,"dst":120,"attack":190,"sev":90,"conf":95,"engine":135,"action":220}
        for col in cols: self.tree.heading(col,text=heads[col]); self.tree.column(col,width=widths[col],anchor="center")
        y=ttk.Scrollbar(tf,orient="vertical",command=self.tree.yview); self.tree.configure(yscrollcommand=y.set); self.tree.pack(side="left",fill="both",expand=True); y.pack(side="right",fill="y")
        cf=ttk.LabelFrame(panels,text="Analítica")
        panels.add(tf,weight=3); panels.add(cf,weight=2)
        self.fig,self.ax=plt.subplots(figsize=(11,2.8)); self.canvas=FigureCanvasTkAgg(self.fig,master=cf); self.canvas.get_tk_widget().pack(fill="both",expand=True)
        self.chart_scroll=ttk.Scrollbar(cf,orient="horizontal",command=self.scroll_chart); self.chart_scroll.pack(fill="x")
        self.legend_frame=ttk.Frame(cf); self.legend_frame.pack(fill="x",pady=(2,0))
        self.chart_points=[]; self.chart_start=0; self.chart_visible=12
    def interfaces(self):
        try:
            options=[]
            for item in LanCapture.interface_details():
                ips=", ".join(item.get("ips", [])) or "sin IP"
                options.append(f"{item['name']} | {ips} | \\Device\\NPF_{item['guid']}")
            self.iface["values"]=options
            preferred=next((i for i, item in enumerate(options) if item.startswith("Wi-Fi |")), 0)
            if options and not self.iface.get(): self.iface.current(preferred)
            if not options: self.status.config(text="Estado: ERROR | No se detectaron interfaces")
        except Exception as e:
            self.status.config(text="Estado: ERROR | No se pudo listar interfaces")
            messagebox.showerror("Interfaces",str(e))
    def start(self):
        if self.capture: return
        try:
            selected=self.iface.get().strip()
            iface=selected.split(" | ")[-1] if selected else None
            self.capture_status="INICIANDO"; self.status.config(text="Estado: INICIANDO | Esperando paquetes...")
            self.capture=LanCapture(self.packet_window,iface,5); self.capture.start()
            self.capture_status="ACTIVO"; self.status.config(text="Estado: ACTIVO | Esperando paquetes...")
            self.lm.config(text="CAPTURA LAN ACTIVA"); self.capture_button.config(state="disabled"); self.stop_button.config(state="normal")
        except Exception as e:
            self.capture=None; self.capture_status="ERROR"; self.status.config(text="Estado: ERROR | Captura no iniciada"); messagebox.showerror("Captura LAN","Revisa Npcap, permisos e interfaz.\n\n"+str(e))
    def stop(self):
        if self.capture: self.capture.stop(); self.capture=None
        self.capture_status="DETENIDO"; self.status.config(text=f"Estado: DETENIDO | Ultima ventana: {self.last_capture_packets} paquetes")
        self.capture_button.config(state="normal"); self.stop_button.config(state="disabled")
        self.lm.config(text="MODELO CARGADO" if self.engine.model_ready else "MODELO NO ENTRENADO")
    def packet_window(self,packets): self.root.after(0,lambda:self.process(packets))
    def process(self,packets):
        if not packets:return
        self.capture_status="ACTIVO"; self.last_capture_packets=len(packets)
        self.status.config(text=f"Estado: ACTIVO | Ultima ventana: {len(packets)} paquetes")
        self.total_packets+=len(packets); t=live_features(packets)
        ds=self.engine.analyze({**t,"failed_logins":0}); src=packets[0]["src_ip"]; dst=packets[0]["dst_ip"]
        for d in ds:
            self.session_threats+=1; self.session_responses+=1
            insert_event({"src_ip":src,"dst_ip":dst,"attack":d.attack,"severity":d.severity,"confidence":d.confidence,
                          "engine":d.source,"action":d.action,"packet_rate":t["packet_rate_raw"],"avg_size":t["avg_size_raw"],
                          "unique_ports":t["unique_ports_raw"],"syn_ratio":t["syn_ratio"],"note":d.reason})
        self.refresh()
    def simulate(self):
        k=random.choice(["scan","bruteforce","dos","hybrid"])
        p={"scan":(130,220,28,.52,1),"bruteforce":(85,320,3,.15,14),"dos":(550,400,4,.91,0),"hybrid":(550,400,28,.92,14)}[k]
        rate,size,ports,syn,failed=p
        t={"packet_rate":math.log1p(rate),"avg_size":math.log1p(size),"unique_ports":math.log1p(ports),"syn_ratio":syn,
           "packet_rate_raw":rate,"avg_size_raw":size,"unique_ports_raw":ports,"failed_logins":failed}
        for d in self.engine.analyze(t):
            self.session_threats+=1; self.session_responses+=1
            insert_event({"src_ip":"192.168.1.50","dst_ip":"192.168.1.1","attack":d.attack,"severity":d.severity,"confidence":d.confidence,
                          "engine":d.source,"action":d.action,"packet_rate":rate,"avg_size":size,"unique_ports":ports,"syn_ratio":syn,"note":d.reason})
        self.refresh()
    def refresh(self):
        for x in self.tree.get_children(): self.tree.delete(x)
        for r in reversed(recent()):
            self.tree.insert("", "end", values=(r[0],r[1],r[2],r[3],r[4],f"{r[5]:.0f}%",r[6],r[7]))
        info=summary(); self.lp.config(text=f"Paquetes: {self.total_packets}"); self.lt.config(text=f"Amenazas sesión: {self.session_threats}"); self.lr.config(text=f"Respuestas: {self.session_responses}")
        rows=timeline_by_attack()
        self.chart_points=sorted({row[0] for row in rows})
        self.chart_visible=min(12,max(4,len(self.chart_points)))
        self.chart_start=min(self.chart_start,max(0,len(self.chart_points)-self.chart_visible))
        self.draw_chart(rows,info)
        self.fig.tight_layout(); self.canvas.draw()
    def scroll_chart(self,*args):
        if not self.chart_points:return
        maximum=max(0,len(self.chart_points)-self.chart_visible)
        if args[0]=="moveto": self.chart_start=round(float(args[1])*maximum)
        elif args[0]=="scroll": self.chart_start=max(0,min(maximum,self.chart_start+int(args[1])*(1 if args[2]=="units" else self.chart_visible)))
        self.refresh()
    def draw_chart(self,rows,info):
        self.ax.clear()
        if not rows:
            self.ax.text(.5,.5,"Sin eventos. Usa Simular ataque o captura LAN.",ha="center",va="center"); self.ax.set_xticks([]); self.ax.set_yticks([]); return
        attacks=sorted({row[1] for row in rows})
        start=self.chart_start; visible=self.chart_points[start:start+self.chart_visible]
        lookup={(hour,attack):count for hour,attack,count in rows}
        values=[[lookup.get((hour,attack),0) for hour in visible] for attack in attacks]
        colors=["#e4572e","#3a86a8","#58a55c","#f2b134","#6c5ce7","#d1495b"]
        for attack,attack_values,color in zip(attacks,values,colors):
            self.ax.plot(range(len(visible)),attack_values,marker="o",linewidth=2,
                         label=attack,color=color)
        self.ax.set_title(f"Amenazas por hora — total={info['total']} / amenazas={info['threats']}",fontsize=round(12*self.ui_scale))
        self.ax.set_ylabel("Detecciones",fontsize=round(10*self.ui_scale))
        self.ax.set_xticks(range(len(visible)),[x[5:] for x in visible],rotation=25,fontsize=round(9*self.ui_scale))
        self.ax.tick_params(axis="y",labelsize=round(9*self.ui_scale))
        self.ax.grid(axis="y",alpha=.25)
        for child in self.legend_frame.winfo_children(): child.destroy()
        for attack,color in zip(attacks,colors):
            item=ttk.Frame(self.legend_frame); item.pack(side="left",padx=8)
            tk.Label(item,text="  ",background=color).pack(side="left",padx=(0,3))
            ttk.Label(item,text=attack).pack(side="left")
        maximum=max(0,len(self.chart_points)-self.chart_visible)
        self.chart_scroll.set(self.chart_start/maximum if maximum else 0,self.chart_start/maximum if maximum else 1)
    def metrics(self):
        p=BASE/"reports"/"metrics.json"
        if not p.exists(): messagebox.showwarning("Métricas","Ejecuta primero: python src/train_model.py"); return
        m=json.loads(p.read_text(encoding="utf-8"))
        messagebox.showinfo("Evaluación del modelo",f"Registros de prueba: {m['test_rows']:,}\n\nAccuracy: {m['accuracy']:.4f}\nPrecision: {m['precision']:.4f}\nRecall: {m['recall']:.4f}\nF1: {m['f1']:.4f}\n\nVer PNG en reports/.")
    def open_graph_search(self):
        dialog=tk.Toplevel(self.root); dialog.title("RADAR-Net | Búsqueda en topología"); dialog.geometry(f"{round(900*self.ui_scale)}x{round(650*self.ui_scale)}")
        controls=ttk.Frame(dialog); controls.pack(fill="x",padx=12,pady=10)
        ttk.Label(controls,text="Algoritmo:").pack(side="left")
        method=tk.StringVar(value="A*"); ttk.Combobox(controls,textvariable=method,values=("BFS","DFS","UCS","Greedy","A*"),state="readonly",width=10).pack(side="left",padx=6)
        ttk.Label(controls,text="Inicio:").pack(side="left",padx=(18,0)); start=tk.StringVar(value=NODES[0])
        ttk.Combobox(controls,textvariable=start,values=NODES,state="readonly",width=23).pack(side="left",padx=6)
        ttk.Label(controls,text="Objetivo:").pack(side="left",padx=(18,0)); goal=tk.StringVar(value=NODES[-1])
        ttk.Combobox(controls,textvariable=goal,values=NODES,state="readonly",width=23).pack(side="left",padx=6)
        canvas=tk.Canvas(dialog,bg="white",height=390,highlightthickness=1,highlightbackground="#c8c8c8"); canvas.pack(fill="both",expand=True,padx=12)
        output=tk.Text(dialog,height=7,wrap="word",state="disabled",font=self.scaled_font(10)); output.pack(fill="x",padx=12,pady=10)
        comparison=ttk.LabelFrame(dialog,text="Comparación de algoritmos"); comparison.pack(fill="x",padx=12,pady=(0,10))
        columns=("algorithm","path","cost","expanded")
        table=ttk.Treeview(comparison,columns=columns,show="headings",height=5)
        headings={"algorithm":"Algoritmo","path":"Camino","cost":"Costo","expanded":"Nodos expandidos"}
        widths={"algorithm":100,"path":510,"cost":70,"expanded":130}
        for column in columns:
            table.heading(column,text=headings[column]); table.column(column,width=widths[column],anchor="center")
        table.pack(fill="x",padx=5,pady=5)
        positions={"PC-Contabilidad":(100,200),"Switch-Piso1":(270,200),"Servidor-Archivos":(450,100),"Firewall-Interno":(450,200),"Switch-Piso2":(450,300),"AP-WiFi-Invitados":(270,340),"Servidor-Financiero":(700,200)}
        def run_search():
            result=search(method.get(),start.get(),goal.get()); canvas.delete("all")
            path_edges=set(zip(result.path,result.path[1:])); path_edges |= {(right,left) for left,right in path_edges}
            for left,right,cost in EDGES:
                x1,y1=positions[left]; x2,y2=positions[right]; active=(left,right) in path_edges
                canvas.create_line(x1,y1,x2,y2,fill="#d62828" if active else "#999999",width=4 if active else 2)
                canvas.create_text((x1+x2)//2,(y1+y2)//2-12,text=str(cost),fill="#b00020",font=self.scaled_font(10,"bold"))
            for node,(x,y) in positions.items():
                color="#2f8f46" if node==start.get() else "#d62828" if node==goal.get() else "#244477"
                canvas.create_oval(x-38,y-22,x+38,y+22,fill=color,outline="white",width=2)
                canvas.create_text(x,y,text=node.replace("-","-\n"),fill="white",font=self.scaled_font(9,"bold"),width=round(72*self.ui_scale))
            path=" -> ".join(result.path) or "Sin ruta"
            text=f"{result.algorithm}: {path}\nCosto total: {result.cost}\nNodos expandidos ({len(result.expanded)}): {', '.join(result.expanded)}"
            output.config(state="normal"); output.delete("1.0","end"); output.insert("1.0",text); output.config(state="disabled")
            for item in table.get_children(): table.delete(item)
            for algorithm in ("BFS","DFS","UCS","Greedy","A*"):
                compared=search(algorithm,start.get(),goal.get())
                table.insert("","end",values=(compared.algorithm," -> ".join(compared.path),compared.cost,len(compared.expanded)))
        ttk.Button(controls,text="Ejecutar búsqueda",command=run_search).pack(side="left",padx=10)
        run_search()
if __name__=="__main__":
    r=tk.Tk(); App(r); r.mainloop()
