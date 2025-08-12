# Disgruntled-Employee

## Example Scenario
Through a social engineering attack, a user was able to gain access to a certain part of the facility. During this time he accessed one of the company computers and was seen interacting with the machine. The security administrators have tasked you to figure out what this individual was doing and if the computer's integrity was compromised in anyway.

## Tools Utilized
- Powershell
- Microsoft Defender (KQL)

---

## IoC Discovery Plan:
1. Check DeviceLogonEvents for any signs of brute force attempts
2. Check DeviceFileEvents for any new files or deleted files
3. Check DeviceProcessEvents to view any commands run

---
## Steps Taken by Bad Actor
1. Logon successfully into machine (credentials compromised via social engineering)
2. Run series of commands to gain information about host machine and network
3. Restart the machine in a futile attempt to erase anything that may have been logged
---

## Steps Taken

1. First look for logon events using the following query (I narrowed down the results by entering in the DeviceName):
```kql
DeviceLogonEvents
| where DeviceName == "rojas-mde"
| order by Timestamp desc
```
The following events results were displayed:
<img width="1639" height="328" alt="image" src="https://github.com/user-attachments/assets/82d87d6e-ab4b-4f89-a6f8-fde2e76fffd2" />
Interestingly, there were no failed logon attempts which means that somehow this individual was able to gain valid credentials without having to brute force them.


2. I checked individually for new files, modified files, and deleted files using the following queries. _Note: When I ran these queries, results were returned due to the environment of the Cyber Range (things like system checks are logged), however, I am excluding them because they are not relevant to the threat hunt._ :
</br>New Files
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where ActionType == "FileCreated"
| order by Timestamp desc
```
</br>Modified Files
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where ActionType == "FileDeleted"
| order by Timestamp desc
```
</br>Deleted Files
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where ActionType == "FileModified"
| order by Timestamp desc
```

No results were returned indicating that the user did not in anyway tamper with the system files.

3. I then searched for any commands run on the system using the following query. _Note: I excluded all "exe" commands to simplify the threat hunting process since all of the "exe" commands were from the nature of the cyber range._ :
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| project Timestamp, DeviceName, ProcessCommandLine
| where ProcessCommandLine !contains "exe"
| order by Timestamp desc
```
The following events were displayed:
<img width="1004" height="617" alt="image" src="https://github.com/user-attachments/assets/c3a2c5ae-73b6-499a-9a7a-430ee39bc48e" />
The commands run by the user are:
</br>```netsh advfirewall firewall show rule name=all```: This command displays the firewall rules
</br>```netstat -a```: This command displays all active network connections and listening ports on the system.
</br>```ipconfig /all```: This command displays a lot of information about the network's configuration including: host IP address, host MAC address, subnet mask, DHCP configuration, DNS server, default gateway, etc.
</br>```ipconfig /displaydns```: Displays recently resolved domain names and their associated IP addresses (essentially showing previously visited websites).
</br>```hostname```: Displays the name of the computer.
</br>```whoami```: Displays the username of the computer.
</br>```whoami /groups```: Lists all the security groups that the user belongs to, along with associated attributes and privilege levels.
</br>```net session```: Displays active SMB (Server Message Block) file sharing sessions on the computer.
</br>```net1 session```: Displays the same information as ```net session``` but is more compatible with legacy systems or programs.

</br>Overall, the user did not exactly do anything malicious, but the series of commands they ran strongly indicate that they were attempting to gain information about the host machine and network. 

---

## Chronological Events

1. The user successfully logged in with compromised credentials
2. The user ran a series of commands to gain technical details of a computer and the network

---

## Summary

An unauthorized individual gained entry into the company facility and it is thought that through a social engineering effort, stole a valid user’s credentials in which he used to login into the machine ```rojas-mde```, and then acquired various details about the network. The individual then left and has not returned since.

---

## Response Taken
The compromised machine ```rojas-mde```, was isolated and an antivirus scan was run. The credentials for the machine were changed and a social engineering info session was scheduled in order to prevent further breaches. Security analysts were notified of the breach in order to closely monitor any attempt of unauthorized access to company resources since the malicious actor was able to gain valid information; however, without network access, their efforts to compromise company security remains restricted.

---

## Created By:
- **Author Name**: Jeremiah Rojas
- **Author Contact**: https://www.linkedin.com/in/jeremiah-rojas-2425532b3
- **Date**: August 8, 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August 8, 2025`  | `Jeremiah Rojas`   
