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
These results confirm that a powershell script was created called ```windows.ps1```. Looking more into the specific event, I found that the script was created/run with Powershell ISE:
<img width="1631" height="300" alt="image" src="https://github.com/user-attachments/assets/770940f0-61aa-40fe-9a54-f43085478ab2" />



2. Next, I searched for any commands that may have been run outside the script; whether from the command prompt or powershell:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where ProcessCommandLine !contains "exe"
| order by Timestamp desc
```

No results were returned indicating that the user may not have run any outside commands. Knowing that the script ```windows.ps1``` was downloaded, I went to the suspect computer and manually looked for the file and found the following:
<img width="1607" height="919" alt="image" src="https://github.com/user-attachments/assets/c92a8cd3-555f-4a6d-b1b0-ecd4a1b66b98" />
Overall, the script does this: 
1. Creates a temporary PowerShell script that just prints a message.
2. Base64-encodes the path to that script (not the script content itself).
3. Launches PowerShell with ```-EncodedCommand```, passing the encoded script path — mimicking how attackers obfuscate commands.
4. Waits 3 seconds, then deletes the script, simulating cleanup or anti-forensics. _Note: the script ```temp_script.ps1``` was logged in Defender most likely because the files creation and deletion was too fast._


3. Afterwards, I check for any network activity using a very basic query:
```kql
DeviceNetworkEvents
| where DeviceName == "rojas-mde"
| order by Timestamp desc
```
No events related to the lab were displayed so I concluded that the only thing the user did was run the script.

---

## Chronological Events

1. The user ran a script that created a sub-script which then executed causing damage to the system and then deleted itself. _Note: This script in itself is being and did not damage to the system._

---

## Summary

A disgruntled employee ran a malicious script on the machine ```rojas-mde``` before leaving the company as a result of being fired. The event was contained and no lasting damage was done.

---

## Response Taken
The compromised machine ```rojas-mde```, was isolated and an antivirus scan was run. Since this event, the IT adminstrators have implemented and enforced a "No script execution" policy for non-admins in order to prevent a malicious script from being run in the future.

---

## Created By:
- **Author Name**: Jeremiah Rojas
- **Author Contact**: https://www.linkedin.com/in/jeremiah-rojas-2425532b3
- **Date**: August 12, 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August 12, 2025`  | `Jeremiah Rojas`   
