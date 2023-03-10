from scapy.all import*  
  
def showPacket(packet):  
    data = '%s' %(packet[TCP].payload)  
    print('+++[%s]: %s' %(packet[IP].dst, data)) 
  
def sniffing(filter):  
    sniff(filter = filter, prn = showPacket, count = 0, store = 0)  
  
if __name__ == '__main__':  
    filter = 'ip tcp port 80'  
    sniffing(filter)  