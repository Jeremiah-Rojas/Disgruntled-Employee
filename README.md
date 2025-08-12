# Disgruntled-Employee

## Example Scenario
Due to recent poor activity, a certain employee was fired. However, since his absence, the computer he used to work with is now acting odd and you believe this is some sort of act of revenge. It is thought that he may have run a script of some sort since there are no rgulations concerning scripts for that particular computer. You job is to figure out what damage the script did the machine.

## Tools Utilized
- Powershell ISE
- Microsoft Defender (KQL)

---

## IoC Discovery Plan:
1. Check DeviceFileEvents for any malicious downloads
2. Check DeviceProcessEvents to view any commands run
3. Check DeviceNetworkEvents for any outbound connections to malicious services

---
## Steps Taken by Bad Actor
1. Run a script designed to negatively impact the machine. For reference, the script is show below:
```
# Simulated Red Team Test Script - Benign
# Author: You (for training/testing purposes)

# Step 1: Create a temporary script file
$tempScript = "$env:TEMP\temp_script.ps1"
"Write-Host 'Hello from the test script'" | Out-File -FilePath $tempScript -Encoding ASCII

# Step 2: Base64-encode the script path (like an attacker might do)
$bytes = [System.Text.Encoding]::Unicode.GetBytes($tempScript)
$encodedCommand = [Convert]::ToBase64String($bytes)

# Step 3: Launch PowerShell with -EncodedCommand (simulated obfuscation)
Start-Process -FilePath "powershell.exe" -ArgumentList "-EncodedCommand $encodedCommand"

# Step 4: Wait briefly, then clean up
Start-Sleep -Seconds 3
Remove-Item -Path $tempScript -Force
```
_Note: You the cybersecurity analyst do not know the this is the script that was run._

---

## Steps Taken

1. First look for any malicious downloads or scripts:
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where FileName contains ".ps1"
| order by Timestamp desc
```
The following events results were displayed:
<img width="1630" height="267" alt="image" src="https://github.com/user-attachments/assets/8c4a39b9-99f9-49b8-aea0-51d37fa71adf" />
These results confirm that a powershell script was created called ```windows.ps1```.


2. Next, I searched for any commands that may have been run outside the script; whether from the command prompt or powershell:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where ProcessCommandLine !contains "exe"
| order by Timestamp desc
```

No results were returned indicating that the user may not have run any outside commands.

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
