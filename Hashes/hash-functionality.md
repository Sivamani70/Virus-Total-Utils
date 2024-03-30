### Script Functionality

### Hash Extraction and Validation:

- Parses the given input file to extract hash values.

### Reputation Assessment:

- Queries a reputable hash reputation service for each valid hash.
- Gathers comprehensive reputation data such as
  - MD5
  - SHA1
  - SHA256
  - FileTag
  - FileDescription
  - TotalChecked
  - Harmless
  - Malicious
  - Suspicious
  - Undetected

### Data Export:

- Organizes the collected hash and their associated reputation information into a structured format.
- Generates a CSV file named "vt-out-hash.csv" within the same directory as the vt-hashes.ps1 script or in the same location from where the script has been initiated.
- If supported by the user machine the script will creates a Excel file instead of csv.

#### Note:

> To Create Excel file user must have installed [Microsoft Office/Office] with Excel on their machine.As the Excel manipulation parts of this script completely rely on Microsoft.Office.Interop.Excel library.
