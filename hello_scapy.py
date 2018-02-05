import json
import time
from multiprocessing import Process, Value
from scapy.all import *
from config import ModbusConfig, MissingConfigField

alive = Value('b', False)

def rd_conf():
    load_contrib('modbus')
    config_path = "modbus_config.json"
    config = ModbusConfig(config_path)
    
def sniff_pkt(alive):
    while alive.value == True:
        pkts = sniff()

def send_pkt():
    send(IP(dst='172.16.26.2')/TCP(dport=503))

if __name__ == '__main__':
    sniff_p = Process(target=sniff_pkt, args=(alive,))
    alive.value = True
    sniff_p.start()
    send_pkt()
    time.sleep(1)
    alive.value = False
    '''
    packet_format = ""
    if config.ip_config_enable == "yes" or "y" or "YES" or "Y":
	packet_format = "IP("
	last = len(config.ip.items())
	for key, value in config.ip.items():
            if value != "" or None:    
		packet_format = packet_format + key + "=" + str(value) + ","
	packet_format = packet_format[:-1] + ")"
    if packet_format != "" and (config.tcp_config_enable == "yes" or "y" or "YES" or "Y"):
	packet_format = packet_format + "/TCP("
	for key, value in config.tcp.items():
	    if value != "" or None:
		packet_format = packet_format + key + "=" + str(value) + ","
	packet_format = packet_format[:-1] + ")"
        #print packet_format
    #eval("sr("+packet_format+")")
    #print pkts
    send(IP(dst='172.16.26.2')/TCP(dport=502)/ModbusADURequest()/ModbusPDU01ReadCoilsResponse())
    wrpcap("modbus_2.pcap", pkts)
    '''
