import sys
from scapy.all import *
 
CNT = 200
p_list = list()
 
def run(target):
    try:
        pkt = rdpcap(target, count=CNT)
    except MemoryError:
        print("Sorry - Memory Error")
        sys.exit()
    numPkt = len(pkt)
 
    print("Analyzing : " + target)
    print("Total Packets: %d\n" % numPkt)
 
    for packet in pkt:
        layer = packet.payload
        p_dict = dict()
        while layer:
            layerName = layer.name
            if layerName == "IP":
                p_dict["srcip"] = layer.src
                p_dict["dstip"] = layer.dst
            if layerName == "TCP":
                if layer.flags == 2 : flags = "SYN"
                if layer.flags == 16 : flags = "ACK"
                if layer.flags == 17 : flags = "FIN,ACK"
                if layer.flags == 18 : flags = "SYN,ACK"
                if layer.flags == 24 : flags = "PSH,ACK"
                p_dict["sport"] = layer.sport
                p_dict["dport"] = layer.dport
                p_dict["seq"] = layer.seq
                p_dict["ack"] = layer.ack
                p_dict["flags"] = flags
            if layerName == "Raw":
                result = processHTTP(layer.load)
                for k,v in result.items() :
                    p_dict[k] = v
 
            layer = layer.payload

            print(p_dict)
 
            if "http" in p_dict :
                p_list.append(p_dict)
                print(p_dict)
 
def processHTTP(data):
    info = dict()
    headers = str(data).splitlines();
    for header in headers:
        if header.startswith("GET") :
            info["http"] = "request"
            info["method"] = header.split()[0]
            info["uri"] = header.split()[1]
        if header.startswith("POST") :
            info["http"] = "request"
            info["method"] = header.split()[0]
            info["uri"] = header.split()[1]
        if header.startswith("HTTP") :
            info["http"] = "response"
            info["status"] = header.split()[1]
 
        if header.startswith("HOST") : info["host"] = header.split(":",1)[1]
        if header.startswith("User-Agent") : info["user-agent"] = header.split(":",1)[1]
        if header.startswith("Referer") : info["referer"] = header.split(":",1)[1]
        if header.startswith("Cookie") : info["cookies"] = header.split(":",1)[1]
 
    return info
 
run("http.pcap")