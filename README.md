# Bulk IOCs Reputation with VirusTotal - PowerShell Script

### Refer to the individual scripts description for functionalities

- Refer to [IP-Functionality](./IPS/ip-functionality.md)
- Refer to [Hash-Functionality](./Hashes/hash-functionality.md)
- Refer to [Domains-Functionality](./Domains/domains-functionality.md)

#### Note:

> The below example specifically talks about running vt-ips.ps1. In the same way you can run any other script for Hashes/Domains.  
> Each script will expect two arguments
>
> - FilePath
> - APIKey
>
> These two arguments are mandatory parameters, and can be provided in any order.  
> FilePath is a text file that contains the IPs/Domains/Hashes. Based on the script executed it will ignore the other types of IOCs  
> For example: while running vt-ips.ps1 script, it will only extracts the IPs from the file and ignore any other values [Hashes/Domains/Any other text values -- are invalid]

## Instructions for running the script

> _Step1:_

1.  Change Windows execution policies to run scripts downloaded from the internet
2.  Open PowerShell as Administrator
3.  Check the current execution policy
    - Type `Get-ExecutionPolicy` and press Enter. This will usually display "`Restricted`" by default.
4.  Change the execution policy
    - To allow running scripts downloaded from the internet, type `Set-ExecutionPolicy RemoteSigned` Press Enter and confirm the change by typing "Y".
5.  Read more about [ExecutionPolicies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1)

## RemoteSigned

- The default execution policy for Windows server computers.
- Scripts can run.
- Requires a digital signature from a trusted publisher on scripts and configuration files that are downloaded from the internet which includes email and instant messaging programs.
- Doesn't require digital signatures on scripts that are written on the local computer and not downloaded from the internet.

> **NOTE: These Scripts are not Digitally Signed and the user must have the Admin permissions to change/set the Execution Policy to Remote Signed**

> _Step2:_

- Run the below command  
  `.\vt-ips.ps1 -FilePath "file_name with the IPs" -APIKEY "YOUR_APIKEY"`
- **_-FilePath_**: takes the path of the file contains the IPs  
   `'.txt' file with each IP separated by new line`

Example: `.\vt-ips.ps1 -FilePath .\malicious-ips.txt -APIKEY "KEY1A2B3C4D"`

### Simpler way

1. Run command `powershell.exe -ExecutionPolicy ByPass -File .\vt-ips.ps1 -FilePath "file_name with the IPs" -APIKEY "YOUR_APIKEY"`
2. **-ExecutionPolicy Bypass**: parameter tells PowerShell to temporarily bypass its default execution policy for this specific command.
3. By using "Bypass," you're instructing PowerShell to ignore any restrictions and run the script, even if it wouldn't normally be allowed.
4. The command essentially says, "Run the script named main.ps1, and while you're at it, ignore any execution policy restrictions that might normally prevent it from running."

Example: `powershell.exe -ExecutionPolicy ByPass -File .\vt-ips.ps1 -FilePath .\malicious-ips.txt -APIKEY "KEY1A2B3C4D"`

## Implementations InProgress

- [x] IP Reputation
- [x] Domains Reputation
- [x] File Hash Reputation
- [ ] URLs Reputation [Not Working issue has to be fixed from VT Team]
