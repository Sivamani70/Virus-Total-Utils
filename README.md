# Bulk IP Reputation with VirusTotal - PowerShell Script

### Script Functionality

### IP Extraction and Validation:

- Parses the given input file to extract IP addresses. Verifies the extracted IP address [IPv4 only as VirusTotal supports only IPv4].

### Reputation Assessment:

- Queries a reputable IP reputation service for each valid IP address.
- Gathers comprehensive reputation data such as
  - IP
  - ASNOwner
  - Country
  - TotalChecked
  - Harmless
  - Malicious
  - Suspicious
  - Undetected

### Data Export:

- Organizes the collected IP addresses and their associated reputation information into a structured format.
- Generates a CSV file named "vt-out-ips.csv" within the same directory as the vt-ips.ps1 script or in the same location from where the script has initiated to store the results.

## Instructions for running the script

> _Step1:_

1.  Change Windows execution policies to run scripts downloaded from the internet
2.  Open PowerShell as Administrator
3.  Check the current execution policy
    - Type `Get-ExecutionPolicy` and press Enter. This will usually display "`Restricted`" by default.
4.  Change the execution policy
    - To allow running scripts downloaded from the internet, type `Set-ExecutionPolicy RemoteSigned` Press Enter and confirm the change by typing "Y".
5.  Read more about [ExecutionPolicies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1)

> _Step2:_

- Run the below command  
  `.\vt-ips.ps1 -FilePath "file_name with the IPs" -APIKEY "YOUR_APIKEY"`
- **_-FilePath_**: takes the path of the file contains the IPs  
   `'.txt' file with each IP seperated by new line`

Example: `.\vt-ips.ps1 -FilePath .\malicious-ips.txt -APIKEY "KEY1A2B3C4D"`

### Simpler way

---

1. Run command `powershell.exe -ExecutionPolicy ByPass -File .\vt-ips.ps1 -FilePath "file_name with the IPs" -APIKEY "YOUR_APIKEY"`
2. **-ExecutionPolicy Bypass**: parameter tells PowerShell to temporarily bypass its default execution policy for this specific command.
3. By using "Bypass," you're instructing PowerShell to ignore any restrictions and run the script, even if it wouldn't normally be allowed.
4. The command essentially says, "Run the script named main.ps1, and while you're at it, ignore any execution policy restrictions that might normally prevent it from running."

Example: `powershell.exe -ExecutionPolicy ByPass -File .\vt-ips.ps1 -FilePath .\malicious-ips.txt -APIKEY "KEY1A2B3C4D"`

## Implementations InProgress

- [x] IP Reputation
- [ ] Domains Reputation
- [ ] File Hash Reputation
