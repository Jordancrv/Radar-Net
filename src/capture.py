import time
from scapy.all import AsyncSniffer,IP,TCP,UDP,conf,get_if_list
from scapy.arch.windows import get_windows_if_list

class LanCapture:
    def __init__(self,callback,iface=None,window_seconds=5):
        self.callback=callback; self.iface=iface; self.window_seconds=window_seconds
        self.buffer=[]; self.start_time=time.time(); self.sniffer=None
    @staticmethod
    def interfaces(): return get_if_list()
    @staticmethod
    def interface_details():
        return [x for x in get_windows_if_list() if x.get("guid")]
    def _pkt(self,pkt):
        if IP not in pkt: return
        now=time.time(); port=None; syn=False
        if TCP in pkt:
            port=int(pkt[TCP].dport); syn=bool(pkt[TCP].flags & 0x02)
        elif UDP in pkt:
            port=int(pkt[UDP].dport)
        self.buffer.append({"time":now,"src_ip":pkt[IP].src,"dst_ip":pkt[IP].dst,
                            "size":len(pkt),"dst_port":port,"syn":syn})
        if now-self.start_time>=self.window_seconds:
            data=self.buffer[:]; self.buffer.clear(); self.start_time=now
            self.callback(data)
    def start(self):
        self.sniffer=AsyncSniffer(iface=self.iface or conf.iface,prn=self._pkt,store=False)
        self.sniffer.start()
    def stop(self):
        if self.sniffer: self.sniffer.stop(); self.sniffer=None
