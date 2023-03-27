from scapy.layers import http
from scapy.all import *
import sys


def pcap_http (file):

    packets = rdpcap(file)
    data_bytes = 0
    new_data_bytes = 0
    http_main_url = ''
    total_http = 0
    for pkt in packets:
        if pkt.haslayer("HTTP"):            
            http_request = pkt.getlayer("HTTPRequest")
            http_response = pkt.getlayer("HTTPResponse")
            if http_request is not None:
                url = "{0[Host]}".format(http_request.fields)    
                url = url.replace("b'","")
                url = url.replace("'","")
                main_url= 'http://' f'{url} '
                data_bytes = int(len(bytes(pkt)))
                new_data_bytes = new_data_bytes + data_bytes
                total_http = total_http + 1
                if main_url not in http_main_url:
                    http_main_url =http_main_url + main_url + " || "
                    
            elif http_response is not None:
                data_bytes = int(len(bytes(pkt)))
                new_data_bytes = new_data_bytes + data_bytes
                total_http = total_http + 1
                          
    print("HTTP REQUEST/RESPONSE FLOWS :",int(total_http))
    print("HTTP DATA BYTES :", new_data_bytes, " BYTES")
    print("HTTP TOP HOSTNAMES ARE :",http_main_url[:-4])


def main(arguments):
    if len(arguments) == 2:        
        pcap_http(arguments[1])



if __name__ == "__main__":
    main(sys.argv)
