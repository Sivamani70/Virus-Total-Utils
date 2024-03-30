## Script Functionality

### IP Extraction and Validation:

- Parses the given input file to extract IP addresses. Verifies the extracted IP address [As VirusTotal supports IPv4 only].

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
- Generates a CSV file named "vt-out-ips.csv" within the same directory as the vt-ips.ps1 script or in the same location from where the script has been initiated.
- If supported by the user machine the script will creates a Excel file instead of csv.

#### Note:

> To Create Excel file user must have installed [Microsoft Office/Office] with Excel on their machine.As the Excel manipulation parts of this script completely rely on Microsoft.Office.Interop.Excel library.
