import json
from scapy.all import *
from config import ModbusConfig, MissingConfigField

def general_packet():
    sr(IP())
if __name__ == '__main__':
    config_path = "modbus_config.json"
    config = ModbusConfig(config_path)
    pkts = sniff(timeout = 3)
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
        print packet_format
    eval("sr("+packet_format+")")
    print pkts
    wrpcap("modbus_2.pcap", pkts)
