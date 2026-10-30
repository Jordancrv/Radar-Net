from scapy.all import get_if_list
for i,x in enumerate(get_if_list(),1): print(f'{i}. {x}')
