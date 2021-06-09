import re
import json
import telnetlib
import requests
import argparse
import getpass

def get_cookies(host,gui_username,gui_password):
	data = {"username": gui_username,"password": gui_password,"html5":"-1"}
	url = f"http://{host}/api/auth/login"
	headers = {'Content-type': 'application/json','accept': 'application/json'}
	session=requests.Session()
	try:
		request = session.post(url,data=json.dumps(data),headers=headers,verify=False)
	except requests.exceptions.RequestException as e: 
		raise SystemExit(e)	

	if request.status_code == 200:
		print("*"*50)
		print("EVE-NG Login Success")
		print("*"*50)
		return request.cookies
	else:
		print(request.json()["message"])
		exit(0)

def get_topology(cookie, host, lab_path):
	url = f"http://{host}/api/labs/{lab_path}/topology"
	headers = {'Content-type': 'application/json','accept': 'application/json'}
	session=requests.Session()
	request = session.get(url, headers=headers, cookies=cookie, verify=False)
	if request.status_code== 200:
		return request.json()
	else:
		print(f"Error getting topology information | {request.json()['message']}")
		exit(0)
	
def get_nodes(cookie, host, lab_path):
	url = f"http://{host}/api/labs/{lab_path}/nodes"
	headers = {'Content-type': 'application/json','accept': 'application/json'}
	session=requests.Session()
	request = session.get(url, headers=headers, cookies=cookie, verify=False)
	nodes = request.json()
	if nodes["code"]== 200:
		down_devices = False
		for device in nodes["data"]:
			status = int(nodes["data"][device]["status"])
			name = nodes["data"][device]["name"]
			if status == 0:
				print(f"{name} is not started, please start the device to continue")
				down_devices = True
		if down_devices == True:
			exit(0)
		else:
			return nodes
	else:
		print(f"Error getting node information | {request.json()['message']}")
		exit(0)
	
def get_ip(nodes,topology):
	node = []
	for key,value in nodes['data'].items():
		node.append(["node"+key,value['name'],value['url'].split(":")[-1],value["template"]])

	neigh = []
	for value in topology['data']:
		#
		src = value["source"]
		src_int = value['source_label'].replace("\\","",1)
		dst = value["destination"]
		dst_int = value['destination_label'].replace("\\","",1)
		#
		src_oct = re.findall("[0-9].*",src)[0]
		dst_oct = re.findall("[0-9].*",dst)[0]
		#
		if int(src_oct) < int(dst_oct):
			src_ip = "10."+ src_oct + "." + dst_oct + "." + src_oct
			neigh.append([src,src_int,src_ip])

			dst_ip = "10."+ src_oct + "." + dst_oct + "." + dst_oct
			neigh.append([dst,dst_oct,dst_ip])
		
		else:
			ip = "10."+ dst_oct + "." + src_oct + "." + src_oct
			neigh.append([src,src_int,ip])

			dst_ip = "10."+ dst_oct + "." + src_oct + "." + dst_oct
			neigh.append([dst,dst_int,dst_ip])

	output = []
	for nodes in node:
		for nei in neigh:
			if nodes[0] == nei[0]:
				output.append(nodes+nei[1:3])
	return output

def get_lab_paths(cookie, host,username,labPath):
	url = f"http://{host}/api/folders/"
	headers = {'Content-type': 'application/json','accept': 'application/json'}
	session=requests.Session()
	request = session.get(url, headers=headers, cookies=cookie, verify=False)
	paths = request.json()

	lab_names = []
	if paths["code"]== 200:
		for lab in paths["data"]["labs"]:
			path = lab["path"]
			filename = lab["file"]
			lab_names.append((filename, path))
	lab_present = False
	for each_lab in lab_names:
		if labPath == each_lab[0]:
			lab_present = True
			labPath = each_lab[1]
	if lab_present == True:
		return labPath
	if lab_present == False:
		print("Lab not found | Listing Available Labs")
		print("*"*50)
		for each_lab in lab_names:
			print(each_lab[0])
		exit(0)

def set_vios_device(port,host):
	tn = telnetlib.Telnet()
	tn.open(host, port)
	tn.write(("\r").encode('ascii'))
	prompt_match = tn.expect([b"#", b">", b": "],timeout=5) #prompt_match[0] = 0 1 2 based on match
	if prompt_match[0] == 2: #initial config prompt
		tn.write(("no\r").encode('ascii'))
	if prompt_match[0] == 1: # > prompt
		tn.write(("en\r").encode('ascii'))
	if prompt_match[0] == 0: # #prompt
		tn.close()

def set_csr1000v_device(port,host):
	tn = telnetlib.Telnet()
	tn.open(host, port)
	tn.write(("\r").encode('ascii'))
	prompt_match = tn.expect([b"#", b">"],timeout=5)
	if prompt_match[0] == 1:  # > prompt
		tn.write(("en\r").encode('ascii'))
	if prompt_match[0] == 0: # #prompt
		tn.close()

def set_xrv_device(port,host):
	tn = telnetlib.Telnet()
	tn.open(host, port)
	tn.write(("\r").encode('ascii'))
	prompt_match = tn.expect([b"#", b"Username: "],timeout=5)
	if prompt_match[0] == 1:  # > prompt
		tn.read_until(b"Username: ", timeout=10)
		tn.write(("cisco\r").encode('ascii'))
		tn.read_until(b"Password: ", timeout=10)
		tn.write(("cisco\r").encode('ascii'))
	if prompt_match[0] == 0: # #prompt
		tn.close()

def set_xrv9k_device(port,host):
	tn = telnetlib.Telnet()
	tn.open(host, port)
	tn.write(("\r").encode('ascii'))
	prompt_match = tn.expect([b"#", b"username: ", b"Username: "],timeout=5)
	if prompt_match[0] == 2:
		tn.read_until(b"Username: ", timeout=10)
		tn.write(("admin\r").encode('ascii'))
		tn.read_until(b"Password: ", timeout=10)
		tn.write(("cisco123\r").encode('ascii'))
	if prompt_match[0] == 1:  # > prompt
		tn.read_until(b"username: ", timeout=10)
		tn.write(("admin\r").encode('ascii'))
		tn.read_until(b"secret:", timeout=10)
		tn.write(("cisco123\r").encode('ascii'))
		tn.read_until(b"secret:", timeout=10)
		tn.write(("cisco123\r").encode('ascii'))
		tn.read_until(b"Username: ", timeout=10)
		tn.write(("admin\r").encode('ascii'))
		tn.read_until(b"Password: ", timeout=10)
		tn.write(("cisco123\r").encode('ascii'))
	if prompt_match[0] == 0: # #prompt
		tn.close()

def set_csr1000vng_device(port,host):
	tn = telnetlib.Telnet()
	tn.open(host, port)
	tn.write(("\r").encode('ascii'))
	prompt_match = tn.expect([b"#", b">", b": "],timeout=5) #prompt_match[0] = 0 1 2 based on match
	if prompt_match[0] == 2: #initial config prompt
		tn.write(("no\r").encode('ascii'))
	if prompt_match[0] == 1: # > prompt
		tn.write(("en\r").encode('ascii'))
	if prompt_match[0] == 0: # #prompt
		tn.close()

def add_configuration(host, port, command, device_type):
	tn = telnetlib.Telnet()
	tn.open(host, port)

	if tn.read_until(b"#", timeout=3):

		if device_type in ["vios", "iol", "csr1000v", "csr1000vng" ]:
			tn.write(("\n\n\n\n").encode('ascii'))
			tn.write(("config t" + "\n" + command + "\n" + "end" +"\n" + "wr" + "\n").encode('ascii'))

		if device_type in ["xrv", "xrv9k"]:
			tn.write(("\n\n\n\n").encode('ascii'))
			tn.write(("config t" + "\n" + command + "\n" + "commit" +"\n" + "end" + "\n").encode('ascii'))

	tn.close()
	
def main(host,gui_username,gui_password,labPath):
	cookie = get_cookies(host,gui_username,gui_password)
	lab_path = get_lab_paths(cookie, host, gui_username,labPath)
	topology = get_topology(cookie, host, lab_path)
	nodes = get_nodes(cookie, host, lab_path)
	ip_interfaces_list = get_ip(nodes,topology)
	
	ip_interfaces_dict = {}

	for each in ip_interfaces_list:
		hostname = each[1]
		port = each[2]
		device_type = each[3]
		interface = each[4]
		ip_address = each[5]
		ip_interfaces_dict.setdefault((hostname,port,device_type), [])
		ip_interfaces_dict[(hostname,port,device_type)].append((interface,ip_address))
		# ip_interfaces_dict = {('CSR1', '32769','csr1000v'): [('Gi1', '10.1.6.1'), ('Gi2', '10.1.9.1')],..}

	#pprint(ip_interfaces_dict)

	for element in ip_interfaces_dict.keys():  #('vIOS13', '32781', 'vios')
		hostname = element[0]
		port = element[1]
		device_type = element[2]

		#seting up device initially
		if device_type == "xrv":
			set_xrv_device(port, host)
		if device_type in ["vios", "iol"]:
			set_vios_device(port, host)
		if device_type == "csr1000v":
			set_csr1000v_device(port, host)
		if device_type == "xrv9k":
			set_xrv9k_device(port,host)
		if device_type == "csr1000vng":
			set_csr1000vng_device(port, host)


		number = re.findall(r"(\d+)$",hostname)[0]

		command = "hostname " + hostname + "\n" 
		command += "interface loopback0" + "\n" + "ip address " + number + "." + number + "." + number + "." + number + " 255.255.255.255\n"
		
		print(f"Configuring {hostname}")

		for interface_ip in ip_interfaces_dict[element]: # [('Gi1', '10.1.6.1'), ('Gi2', '10.1.9.1')]
			command += f"interface {interface_ip[0]}\n ip address {interface_ip[1]} 255.255.255.0\n no shut\n"
		
		if device_type in ["vios", "iol", "csr1000v", "csr1000vng", "xrv", "xrv9k"]:
			add_configuration(host,port,command,device_type)
		else:
			print(f"Unsupported device, skipping {hostname}")

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-u", "--username", required=True)
	parser.add_argument("-i", "--eve_IP", required=True)
	parser.add_argument("-l", "--lab_path", required=True)
	args = parser.parse_args()

	gui_username = args.username
	host = args.eve_IP
	labPath = args.lab_path
	gui_password = getpass.getpass("Enter EVE-NG GUI Password: ")
	
	if gui_password:
		main(host,gui_username,gui_password,labPath)

	else:
		print("No password entered!")
		exit(0)
