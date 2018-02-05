import json
import time
import ctypes
import threading
from scapy.all import *
from config import ModbusConfig, MissingConfigField

def rd_conf():
    load_contrib('modbus')
    config_path = "modbus_config.json"
    config = ModbusConfig(config_path)
    
def sniff_pkt():
    global pkts
    pkts = sniff(timeout=2)

def send_pkt():
    send(IP(dst='172.16.26.2')/TCP(dport=502))

def wr_pcap():
    times_2 = 0
    while times_2 < 20:
        if thread_1.is_alive() == False:
            break
        else:
            times_2 += 1
            time.sleep(0.2)
    wrpcap("modbus.pcap", pkts)

if __name__ == '__main__':
    #lock = threading.Lock()
    thread_1 = threading.Thread(target=sniff_pkt)
    thread_1.start()
    thread_2 = threading.Thread(target=send_pkt)
    thread_2.start()
    wr_pcap()
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
