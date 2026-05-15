from scapy.all import *
import logging

# 设置日志记录的级别和格式
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

def pack_callback(packet):
#    print ( packet.show() )
#    if packet['Ether'].payload:
        # print(packet)
#        print (packet['Ether'].src)
#        print("is arp:")
#        print (packet['Ether'].dst)
#        print("is arp:")
#        print (packet['Ether'].type)

    if packet.haslayer('IP'):
        print("is IP:")
        ip_packet = packet['IP']
        print("IPv4 Packet:")
        print("Source IP:", ip_packet.src)
        print("Destination IP:", ip_packet.dst)
    logging.debug("Received packet: %s", packet.summary())
    wrpcap("./netdata/captured_traffic.pcap", packet, append=True)

def capture(number):
#    os.remove("./netdata/captured_traffic.pcap")
    filterstr="tcp||udp"
    #filter=filterstr
    logging.info("Start capturing packets...")
    B = sniff(iface="WLAN", count=number, filter=filterstr, prn=pack_callback,timeout=10)
    logging.info("Capture finished.")
    return True

#print(capture(100))