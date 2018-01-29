import json
from scapy.all import *
from config import ModbusConfig, MissingConfigField

def general_packet():
    sr(IP())
if __name__ == '__main__':
    config_path = "modbus_config.json"
    config = ModbusConfig(config_path)
    if config.ip_config_enable == "yes":
	packet_format = "IP("
	for key, value in config.ip.items():
            if 
                packet_format = packet_format + key + "=" + value + ")"
    eval("sr1("+packet_format+")")
