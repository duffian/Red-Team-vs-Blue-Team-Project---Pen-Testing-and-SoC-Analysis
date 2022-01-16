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

`nmap 192.168.1.90/24`

![image]()

#### Service and Version Scan ####


'nmap -A --script-vuln -v 192.168.1.105`

![image]()

#### Navigate Webserver ####

`dirb http://192.168.1.105`

![image]()

Access `http://192.168.1.105` via VM web browser

![image]()

Navigate directories to ID the file containing information about the secret directory

![image]()

Brute force the password for the hidden directory using the ‘hydra’ command and access the secret folder 

`hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get “/company_folders/secret_folder/”`

![image]()

Break the hashed password using crackstation.net
![image]()
![image]()

SSH into Ashton's account to locate flag
`ssh ashton@192.168.1.105`
![image]()
![image]()
![image]()
![image]()
![image]()





Connect to the server via WebDAV
Useername: `ryan`
Password: `linux4u`
![image]()
![image]()

Upload a PHP reverse shell payload

Create ‘shell.php’ shell script
![image]()


Upload payload to WebDAV system
![image]()
![image]()
![image]()
![image]()

Execute payload that you uploaded to the site to open up a meterpreter session

Setup listener
![image]()
![image]()
![image]()

Once ‘shell.php’ shell script is uploaded to target website and is clicked on, attacking Kali machine will connect
![image]()

Meterpreter session is now open
![image]()

Acquire interactive reverse shell
‘shell’
![image]()

Find and capture flag
![image]()
![image]()

Exit back to meterpreter session
![image]()

Download ‘flag.txt’ to Kali machine
![image]()



---


### Blue Team: Log Analysis and Attack Characterization



### Hardening: Proposed Alarms and Mitigation Strategies
