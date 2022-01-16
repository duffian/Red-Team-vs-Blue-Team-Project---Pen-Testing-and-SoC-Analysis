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
## Exploitation ## 
---
Discover target IP
`ifconfig`
`netdiscover -Pr 192.168.1.0/16`
`nmap 192.168.1.90/24`




### Blue Team: Log Analysis and Attack Characterization



### Hardening: Proposed Alarms and Mitigation Strategies
