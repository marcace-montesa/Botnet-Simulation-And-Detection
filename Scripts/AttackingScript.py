from scapy.all import * 
import sys
import time
import math
import random
conf.verb = 0

target_ip = "192.168.56.104" #Replace with target IP
attk = ["100","107","106","105","1"] #Should be replaced with the last digits of each attacking machine.

while True:
	userinput = input("what type of attack would you like ")

	if (userinput == "1") or ("ping" in userinput.lower()):
		#do ping flood attack
		
		while(True):
			source = RandIP("192.168.56.1/24")
			source_check = str(source).split(".")
			if source_check[3] not in attk:
				packet = IP(src = ".".join(source_check), dst = target_ip) / ICMP()
				reply = sr1(packet, timeout = 2)

	elif (userinput == "2") or ("full" in userinput.lower()):
		#do syn scan

		while(True):
			source = RandIP("192.168.56.1/24")
			source_check = str(source).split(".")
			if source_check[3] not in attk:
				#print(source_check[3])
				p = sr1(IP(src = ".".join(source_check), dst = target_ip) / TCP(sport = RandShort(), dport = RandShort(), flags = "S"), timeout = 0.1)


	elif (userinput == "3") or ("xmas" in userinput.lower()):
		#do full xmas scan

		while(True):
			source = RandIP("192.168.56.1/24")
			source_check = str(source).split(".")
			if source_check[3] not in attk:
				xmas_scan = sr1(IP(src = ".".join(source_check), dst = target_ip) / TCP(dport = RandShort(), flags = "FPU"), timeout = 0.1)

				#print(type(xmas_scan))

				if(str(type(xmas_scan)) == "<class 'NoneType'>"):
					print ("Open / Filtered")
				elif(xmas_scan.haslayer(TCP)):
					if(xmas_scan.getlayer(TCP).flags == 0x14):
						print("Closed")
				elif(xmas_scan.haslayer(ICMP)):
					if(int(xmas_scan.getlayer(ICMP).type) == 3 and int(xmas_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]):
						print("Filtered")


	elif (userinput == "4") or ("null" in userinput.lower()):
		#do full null scan

		while(True):
			source = RandIP("192.168.56.1/24")
			source_check = str(source).split(".")
			if source_check[3] not in attk:
				null_scan = sr1(IP(src = ".".join(source_check), dst = target_ip)/TCP(dport = RandShort(), flags = ""), timeout = 0.1)

				if(str(type(null_scan))=="<class 'NoneType'>"):
					print ("Open / Filtered")
				elif(null_scan.haslayer(TCP)):
					if(null_scan.getlayer(TCP).flags == 0x14):
						print("Closed")
				elif(null_scan.haslayer(ICMP)):
					if(int(null_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]):
						print("Filtered")

	elif (userinput == "5") or ("fin" in userinput.lower()):
		#do full fin scan

		while(True):
			source = RandIP("192.168.56.1/24")
			source_check = str(source).split(".")
			if source_check[3] not in attk:
				fin_scan = sr1(IP(src = ".".join(source_check), dst = target_ip) / TCP(dport = RandShort(), flags = "F"), timeout = 0.1)

				if(str(type(fin_scan)) == "<class 'NoneType'>"):
					print("Open / Filtered")
				elif(fin_scan.haslayer(TCP)):
					if(fin_scan.getlayer(TCP).flags == 0x14):
						print("Closed")
				elif(fin_scan.haslayer(ICMP)):
					if(int(fin_scan.getlayer(ICMP).type) == 3 and int(fin_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]):
						print("Filtered")

	elif (userinput == "6") or ("ack" in userinput.lower()):
		#do full ack scan

		while(True):
			source = RandIP("192.168.56.1/24")
			source_check = str(source).split(".")
			if source_check[3] not in attk:
				ack_scan = sr1(IP(src = ".".join(source_check), dst = target_ip) / TCP(dport = RandShort(), flags = "A"), timeout = 0.1)

				if(str(type(ack_scan)) == "<class 'NoneType'>"):
					print("Filtered Firewall")
				elif(ack_scan.haslayer(TCP)):
					if(ack_scan.getlayer(TCP).flags == 0x4):
						print("No Firewall")
				elif(ack_scan.haslayer(ICMP)):
					if(int(ack_scan.getlayer(ICMP).type) == 3 and int(ack_flag.getlayer(ICMP).code) in [1,2,3,9,10,13]):
						print("Firewall Present")

	elif (userinput == "0") or ("exit" in userinput.lower()):
		#exit
		break