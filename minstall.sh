#!/bin/bash

cat << "EOF"
        _           _        _ _ 
  /\/\ (_)_ __  ___| |_ __ _| | |
 /    \| | '_ \/ __| __/ _` | | |
/ /\/\ \ | | | \__ \ || (_| | | |
\/    \/_|_| |_|___/\__\__,_|_|_|


EOF

echo "[+]---Update----------------------------------"
sudo apt update

echo "[+]---Changement de la source-----------------"
echo deb http://ftp.free.fr/pub/kali kali-rolling main contrib non-free non-free-firmware | sudo tee /etc/apt/sources.list

echo "[+]---Apt install-----------------------------"
sudo apt install seclists bloodhound wafw00f ruby python-pip python3 python3-pip python3-argcomplete xclip netexec
sudo apt install go pipx

echo "[+}---Git Clone & wget------------------------"
echo "[+]---Create TOOLS Folder...------------------"
cd $HOME
mkdir TOOLS  && cd TOOLS


####  WORDLISTS ####
cd $HOME/TOOLS
mkdir WORDLISTS && cd WORDLISTS
## Usernames
wget https://raw.githubusercontent.com/urbanadventurer/username-anarchy/master/username-anarchy
git clone https://github.com/urbanadventurer/username-anarchy.git
## Wordlists
git clone https://github.com/Mebus/cupp.git
git clone https://github.com/digininja/RSMangler.git
########wget https://raw.githubusercontent.com/digininja/RSMangler/master/rsmangler.rb
git clone https://github.com/sc0tfree/mentalist.git
##DEFAULT
sudo pip3 install defaultcreds-cheat-sheet
#creds search tomcat


#### CMS ####
cd $HOME/TOOLS
mkdir CMS && cd CMS
#git clone https://github.com/SamJoan/droopescan.git
sudo pip install droopescan
## WORDPRESS
sudo gem install terminal-table
git clone https://github.com/delvelabs/vane.git
## JOOMLA
git clone https://github.com/0rbz/JoomBrute.git
wget https://raw.githubusercontent.com/ajnik/joomla-bruteforce/master/joomla-brute.py
git clone https://github.com/rezasp/joomscan.git
#cd joomscan
#perl joomscan.pl
git clone https://github.com/drego85/JoomlaScan.git
##TOMCAT
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
wget https://raw.githubusercontent.com/b33lz3bub-1/Tomcat-Manager-Bruteforce/master/mgr_brute.py


#### Obfuscator ####
cd $HOME/TOOLS
mkdir obfuscator && cd obfuscator
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
sudo python3 setup.py install --user
cd ..
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
git clone https://github.com/bats3c/darkarmour.git
cd ..

## AD
cd $HOME/TOOLS
mkdir AD && cd AD
git clone https://github.com/CiscoCXSecurity/linikatz.git
git clone https://github.com/FSecureLABS/SharpGPOAbuse.git
git clone https://github.com/Ridter/noPac.git
git clone https://github.com/SnaffCon/Snaffler.git
mkdir PrintNightmare && cd PrintNightmare &&wget https://raw.githubusercontent.com/cube0x0/CVE-2021-1675/main/CVE-2021-1675.py
cd ..
git clone https://github.com/topotam/PetitPotam.git
cd ..

###impacket exe
cd $HOME/TOOLS
git clone https://github.com/maaaaz/impacket-examples-windows.git

#### LINUX ####
cd $HOME/TOOLS
mkdir linux && cd linux
git clone https://github.com/huntergregal/mimipenguin.git
git clone https://github.com/galkan/crowbar.git

#### SSL ####
cd $HOME/TOOLS
mkdir ssl && cd ssl
sudo pip3 install shcheck
git clone --depth 1 https://github.com/drwetter/testssl.sh.git


#### HTTP ####
cd $HOME/TOOLS
mkdir http && cd http
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
git clone https://github.com/FSecureLABS/GWTMap.git
git clone https://github.com/Dheerajmadhukar/4-ZERO-3.git
git clone https://github.com/devploit/dontgo403.git
## XSS
git clone https://github.com/s0md3v/XSStrike.git
git clone https://github.com/rajeshmajumdar/BruteXSS.git
##identywaf
wget https://raw.githubusercontent.com/stamparm/identYwaf/master/identYwaf.py
##webshell php cool
wget https://raw.githubusercontent.com/Arrexel/phpbash/master/phpbash.min.php
wget https://raw.githubusercontent.com/Arrexel/phpbash/master/phpbash.php
## Splunk
git clone https://github.com/0xjpuff/reverse_shell_splunk.git
## LFI
git clone http://github.com/mzfr/liffy
cd liffy
sudo pip3 install -r requirements.txt
cd ..
git clone https://github.com/OsandaMalith/LFiFreak.git
echo "CHECK LFISUITE"
git clone https://github.com/D35m0nd142/LFISuite.git
cd ..

#### ALL ####
cd $HOME/TOOLS
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

#### DNS ####
cd $HOME/TOOLS
mkdir DNS && cd DNS
git clone https://github.com/Kinjutsu00/DnsExfiltration.git
git clone https://github.com/Arno0x/DNSExfiltrator.git
git clone https://github.com/TheRook/subbrute.git
cd ..

#### TUNNELING ####
cd $HOME/TOOLS
mkdir tunneling && cd tunneling
git clone https://github.com/nccgroup/SocksOverRDP.git
git clone https://github.com/utoni/ptunnel-ng.git
go install github.com/jpillora/chisel@latest
git clone https://github.com/klsecservices/rpivot.git
cd rpivot && wget https://github.com/klsecservices/rpivot/releases/download/v1.0/client.exe
cd ..
git clone https://github.com/iagox86/dnscat2.git
wget https://github.com/nicocha30/ligolo-ng/archive/refs/tags/v0.4.4.zip
unp v0.4.4.zip
cd ligolo-ng-0.4.4
#go build -o agent cmd/agent/main.go
go build -o proxy cmd/proxy/main.go
CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o agent cmd/agent.main.go
echo " [LIGOLO] your username :"
read username_ligolo
sudo ip tuntap add user $username_ligolo mode tun ligolo
sudo ip link set ligolo up
cd ..


### PRIVESC ####
cd $HOME/TOOLS
##LINUX
mkdir privesc && cd privesc
git clone https://github.com/lefayjey/linWinPwn
cd linWinPwn; chmod +x linWinPwn.sh
cd ..
apt install pipx git
pipx ensurepath
sudo pipx install git+https://github.com/Pennyw0rth/NetExec
###LinEnum
git clone https://github.com/rebootuser/LinEnum.git
apt install python3-pip && sudo apt-get install libpcap-dev && sudo pip3 install Cython && sudo pip3 install python-libpcap
git clone https://github.com/DanMcInerney/net-creds.git
git clone https://github.com/whotwagner/logrotten.git
git clone https://github.com/DominicBreuker/pspy.git
git clone https://github.com/The-Z-Labs/linux-exploit-suggester.git
git clone https://github.com/arthepsy/CVE-2021-4034.git
git clone https://github.com/blasty/CVE-2021-3156.git
git clone https://github.com/dirtycow/dirtycow.github.io.git
cd ..
##WINDOWS
###LAZAGNE
git clone https://github.com/AlessandroZ/LaZagne.git
cd LaZagne
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe
wget https://raw.githubusercontent.com/AlessandroZ/LaZagne/master/Linux/laZagne.py
cd ..


clear

cat << "EOF"
ALL
 |
 |-PayloadAllTheThings          Bible bru
 |-Defaults                     $ creds search tomcat

PRIVESC
 |
 |-net-creds                    sniff data from int or pcap
 |-CVE-2021-4034                pkexec poc
 |-CVE-2021-3156                sudo abuse
 |-dirty-cow                    dirtycow
 LIN
  |-Linux-exploit-suggester     Linux exploit sugg
  |-LinEnum                     Local linux enum & privesc
  |-pspy                        spy ps
 WIN
  |-PCredz                      Extract info such as Credt,NTLM,...
  |-LogRotten                   Log rotate vuln
  |-NoPac                       Special vuln
  |-PrintNightmare              Special vuln
  |-PetitPotam                  Special vuln

AD
 |
 |-Linikatz
 |-SharpGPOAbuse                GPO_abuse
 |-Impacket-examples-windows    impacket_exe
 |-Snaffler                     find candy creds, ..
 |-NetExec                      New CrackMapExec
 |-linWinPwn                    Automate AD scanner

LINUX
 |
 |-mimipenguin                  show credentials (admin)
 |-Crowbar                      bruteforce SSH Key
 |-linux-exploit-suggester      LINUX suggester

SSL
 |
 |-shcheck                      check security attributes
 |-testssl                      test SSL vulnerabilities

HTTP
 |
 |-interactsh                   OOB interaction gathering
 |-GWTMap                       GoogleWebToolkit Map
 |-4-ZERO-3                     403 bypass SH
 |-Dontgo403                    403 bypass go
 |-Identywaf                    identy WAF
 |-phpbash.min.php              Rev shell cool
 |-phpbash.php
 |-reverse_shell_splunk         Rev shell splunk
 XSS
  |-XSStrike                    Cool XSS scanner
  |-BruteXSS                    bruteforce XSS
LFI
 |-LFiFreak                     LFI exploiter bind/reverse shell
 |-LFISuite                     Automatic LFI (python relou)
 |-liffy                        LFI Tool

WORDLISTS
 |
 USERNAMES
  |-username-anarchy            Create usernames with infos
 PASSWORDS
  |-cupp                        Famous bro
  |-rsmangler.rb                manipulation on word, wordlists
  |-mentalist                   Graphic tool wordlist gen

CMS
 |
 |-Droopescan                   Scanner CMS
 WORDPRESS
  |-vane                        Wpscan like
 JOOMLA
  |-Joomla-brute.py             Joomla login bruteforce
  |-JoomBrute                   quite same
  |-Joomscan                    OWASP Joomla vuln scan
  |-Joomlascan                  Find component in joomlaCMS
 TOMCAT
  |-cmd.jsp                     revshell
  |-mgr_brute                   Brute creds tomcat

DNS
 |
 |-DnsExfiltration              Dns Exfiltrator
 |-DnsExfiltrator               Same but different
 |-subbrute                     enum DNS records & subs

TUNNELING
 |
 |-SocksOverRDP                 Socks4/5 over RDP/CITRIX/..
 |-ptunnel-ng                   TCP through ICMP
 |-chisel                       TCP/UDP tunnel over HTTP
 |-dnscat2                      DNS tunnel
 |-Ligolo-ng                    La base

OBFUSCATOR
 |-Darkarmour                   Windows AV Evasion
 |-Bashfuscator                 Bash fuscation framework linux cmd
 |-Invoke-DOSfuscation          cmd.exe obf & detect
EOF
