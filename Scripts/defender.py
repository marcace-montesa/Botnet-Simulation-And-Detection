import subprocess
import sys

ip_addresses = []
attack = ""

with open("final/alert","rt") as file1:
	lines = file1.readlines()
	for line in lines:
		if "[**]" in line:
			line = line.split(" ")
			attack = line[2]
		if "192.168.56.104" in line:
			line = line.split(" ")
			if line[0].split(":")[0] not in ip_addresses:
				if line[0].split(":")[0] != "192.168.56.104":
					ip_addresses.append(line[0].split(":")[0])

real_hosts = []

commands = ['fping']

for i in ip_addresses:
	commands.append(i)

p = subprocess.Popen(commands, stdout = subprocess.PIPE ,stderr = subprocess.DEVNULL)
output, err = p.communicate()
outputstr = str(output)
outputstr = outputstr[2:].split("\\n")[:-1]

#print(outputstr)
for i in outputstr:
	if "alive" in i:
		i = i.split(" ")
		real_hosts.append(i[0])


if len(real_hosts) > 1:
	print("botnet")
	commands = ["iptables","-N","LOGGING"]
	p = subprocess.Popen(commands, stdout = subprocess.PIPE)
	commands = ["iptables","-A","INPUT","-j","LOGGING"]
	p = subprocess.Popen(commands, stdout = subprocess.PIPE)
	commands = ["iptables","-A","LOGGING","-p","tcp","-m","limit","--limit","5/minute","-j","LOG","--log-prefix","'IPTables Dropped: '","--log-level","4"]
	p = subprocess.Popen(commands, stdout = subprocess.PIPE)
	commands = ["iptables","-A","LOGGING","-j","DROP"]
	p = subprocess.Popen(commands, stdout = subprocess.PIPE)
else: 
	print("not botnet")
	commands = ["iptables","-N","LOGGING"]
	p = subprocess.Popen(commands, stdout = subprocess.PIPE)
	commands = ["iptables","-A","INPUT","-s",real_hosts[0],"-j","LOGGING"]
	p = subprocess.Popen(commands, stdout = subprocess.PIPE)
	commands = ["iptables","-A","LOGGING","-p","tcp","-m","limit","--limit","5/minute","-j","LOG","--log-prefix","'IPTables Dropped: '","--log-level","4"]
	p = subprocess.Popen(commands, stdout = subprocess.PIPE)
	commands = ["iptables","-A","LOGGING","-j","DROP"]
	p = subprocess.Popen(commands, stdout = subprocess.PIPE)

print(attack+" Attack Detected, IPTables Updated. Stopping incoming traffic for 30 seconds.")
	
