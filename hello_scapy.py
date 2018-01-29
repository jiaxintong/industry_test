from scapy.all import *
from config import ModbusConfig, MissingConfigField

def general_packet():
    sr(IP())

if __name__ == '__main__':
    general_packet() 
    config_path = "modbus_config.json"
    config = ModbusConfig(config_path)
    print("It is Good!" + config.port)

