from scapy.all import*
import tempfile
  
protocols = {1:'ICMP', 6:'TCP', 17:'UDP'}  

count = 1
sniffing_time = input("Sniffing Time: ")
  
def showPacket(packet):    
    global count

    # packet[0][1].display()
    # IP HEADER
    src_ip = packet[0][1].src  
    dst_ip = packet[0][1].dst  
    proto = packet[0][1].proto
    ttl = packet[0][1].ttl
    length = packet[0][1].len

    if proto in protocols:

        # TCP
        if proto == 6:   

            is_http = True

            # TCP HEADER
            sport = packet[0][2].sport
            dport = packet[0][2].dport
            seq = packet[0][2].dport
            ack = packet[0][2].ack
            flag = packet[0][2].flags

            try : 
                # HTTP HEADER
                host = packet[0][3].Host.decode("utf-8")
                date = packet[0][3].Date

                print("==<IP HEADER>==")
                print("protocol: %s: %s -> %s" %(protocols[proto], src_ip, dst_ip))
                print("src: %s -> dst: %s" %(src_ip, dst_ip))
                print("TTL: %s Length: %s" %(ttl, length))
                print('==<TCP HEADER>==')
                print("sport: %s dport: %s" %(sport, dport))    
                print("seq: %s ack: %s flag: %s" %(seq, ack, flag))
                print("==<HTTP HEADER>==")
                print(f'HOST : {host}')
                print(f'DATE : {date}')
                print("\n")
            except:
                is_http = False
            
            if not is_http:
                try : 
                    payload = packet[0][3].load
                    data = payload.decode('UTF-8')
                    info_list = data.split("\r\n")

                    # HTTP HEADER
                    headers = []

                    for info in info_list:
                        if "Server" in info :
                            headers.append(info)
                        if "Date" in info : 
                            headers.append(info)
                        if "Content-Type" in info :
                            headers.append(info)
                        if "Transfer-Encoding" in info :
                            headers.append(info)
                        if "Connection" in info:
                            headers.append(info)
                        if "Location" in info :
                            headers.append(info)
                        if "Vary" in info :
                            headers.append(info)
                        if "Accept" in info :
                            headers.append(info)
                        if "User-Agent" in info :
                            headers.append(info)
                        if "Host" in info :
                            headers.append(info)
                        if "Cache-Control" in info :
                            headers.append(info)
                        if "Pragma" in info :
                            headers.append(info)
                        if "Cross-Origin-Opener-Policy-Report-Only" in info :
                            headers.append(info)
                        if "Expires" in info :
                            headers.append(info)
                        if "Content-Length" in info :
                            headers.append(info)
                        if "X-XSS-Protection" in info :
                            headers.append(info)
                        if "X-Frame-Options" in info :
                            headers.append(info)
                        
                    if len(headers) != 0:
                        print("==<IP HEADER>==")
                        print("protocol: %s: %s -> %s" %(protocols[proto], src_ip, dst_ip))
                        print("src: %s -> dst: %s" %(src_ip, dst_ip))
                        print("TTL: %s Length: %s" %(ttl, length))
                        print('==<TCP HEADER>==')
                        print("sport: %s dport: %s" %(sport, dport))    
                        print("seq: %s ack: %s flag: %s" %(seq, ack, flag))
                        print("==<HTTP HEADER>==")
                        for header in headers :
                            print(header)
                        print('\n')                     
                except : 
                    pass
                
    count += 1
  
def sniffing(filter):
    print("Sniffing Start")
    pcap_file = sniff(prn = showPacket,timeout=int(sniffing_time), filter = filter, count=0)
    print("Finish Capture Packet")
    if count == 1:
            print("No Packet")
            sys.exit()
    else:
        print("Total Packet: %s" %(count-1))
        file_name = input("Enter File Name: ")
        wrpcap(str(file_name), pcap_file)
  
if __name__ == '__main__':  
    filter = 'port 80'  
    sniffing(filter)