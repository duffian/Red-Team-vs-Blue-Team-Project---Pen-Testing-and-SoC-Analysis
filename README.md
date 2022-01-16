# RedTeam_vs_BlueTeam
# Security Assessment, Analysis, and Hardening Project
This Red Team vs. Blue Team project is organized into the following sections:
- **Network Topology** Red Team vs. Blue Team live network environment
- **Red Team** Security Assessment
- **Blue Team** Log Analysis and Attack Characterization
- **Hardening** Proposed Alarms and Mitigation Strategies
___

In this activity, Red Team acts as a malicious actor attempting to gain unauthorized access to a network. Blue Team monitors and analyses the activity. The ultimate objective is for Blue Team to identify vulnerabilities and to improve network security. 

### Network Topology

In this environment Blue Team is defending against Red Team attacks.
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/3122a604b745c825d67c88767017092a2c29fa79/images/RvBNetworkTopology.png)

|  IP                     |  Machine              |  OS          |  Role                              |
|  -----------------------|:---------------------:|:------------:|:----------------------------------:|
|  192.168.1.0/24         | Network Address Range |              |                                    |
|  255.255.255.0          | Netmask               |              |                                    |
|  192.168.1.1            | Azure Hyper-V         | Windows 10   | Host Machine                       |
|  192.168.1.90           | Kali Linux            | Linux 2.6.32 | Attacking Machine                  |
|  192.168.1.100          | ELK-Stack             | Linux        | Network Monitoring / Kibana        |
|  192.168.1.105          | Capstone              | Linux        | Target Machine / Vulnerable Server |


---


### Red Team: Security Assessment
---
#### Exploitation #### 
---
Discover target IP
`ifconfig`

`netdiscover -Pr 192.168.1.0/16`
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/netdiscover.png)

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/netdiscover2.png)

`nmap 192.168.1.90/24`
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/nmap.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/nmap2.png)


#### Service and Version Scan ####

'nmap -A --script-vuln -v 192.168.1.105`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/nmap-a.png)

#### Navigate Webserver ####

`dirb http://192.168.1.105`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/dirb.png)

Access `http://192.168.1.105` via VM web browser

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/browse1.png)

Navigate directories to ID the file containing information about the secret directory

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/browse2.png)

#### Brute Force ####
Brute force the password for the hidden directory using the ‘hydra’ command and access the secret folder 

`hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get “/company_folders/secret_folder/”`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/hydra1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/hydra2.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/secfolder1.png)

#### Password Hash ####

Break the hashed password using crackstation.net
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/crack1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/crack2.png)

#### SSH ####

SSH into Ashton's account to locate flag
`ssh ashton@192.168.1.105`
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/ssh1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/ssh2.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/ssh3.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/ssh4.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/ssh5.png)

#### WebDAV ####

Connect to the server via WebDAV
Useername: `ryan`
Password: `linux4u`
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/webdav1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/webdav2.png)

#### Reverse Shell ####

Upload a PHP reverse shell payload

Create ‘shell.php’ shell script

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/revshell1.png)

Upload payload to WebDAV system
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/revshell2.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/revshell3.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/revshell4.png)

Execute payload that you uploaded to the site to open up a meterpreter session

Setup listener

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list2.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list3.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list4.png)

Once ‘shell.php’ shell script is uploaded to target website and is clicked on, attacking Kali machine will connect
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/shellupload.png)

Meterpreter session is now open
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/meterpretersession_open.png)

Acquire interactive reverse ‘shell’
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/intrevshell.png)

Find and capture flag
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/flg1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/flg2.png)

Exit back to meterpreter session
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/exitbackmeterpreter.png)

Download ‘flag.txt’ to Kali machine
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/dwnlodflg.png)


---


### Blue Team: Log Analysis and Attack Characterization



### Hardening: Proposed Alarms and Mitigation Strategies
