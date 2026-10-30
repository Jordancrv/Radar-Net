class RuleEngine:
    def evaluate(self, packet_rate, unique_ports, failed_logins, syn_ratio):
        alerts=[]
        if unique_ports>=15:
            alerts.append({"type":"PORT SCAN","severity":"ALTO","confidence":94,
                           "reason":f"Se observaron {unique_ports} puertos destino."})
        if failed_logins>=8:
            alerts.append({"type":"BRUTE FORCE","severity":"ALTO","confidence":91,
                           "reason":f"Se observaron {failed_logins} intentos fallidos."})
        if packet_rate>=250 and syn_ratio>=0.65:
            alerts.append({"type":"SYN FLOOD / DOS","severity":"CRITICO","confidence":97,
                           "reason":f"Tasa={packet_rate:.0f} pkt/s; SYN ratio={syn_ratio:.2f}."})
        return alerts
