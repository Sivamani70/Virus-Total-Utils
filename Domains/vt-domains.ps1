[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String] $APIKEY,
    [Parameter(Mandatory)]
    [String] $FilePath
)

class VTDomainReputation {
    [String] $filePath
    [System.Collections.Generic.List[String]] $listOfDomains
    [System.Collections.Generic.List[PSCustomObject]] $responseObj
    [System.Object[]] $content
    [Hashtable] $headers = @{}
    [String] $validator = "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$"
    [String] $ENDPOINT = "https://www.virustotal.com/api/v3/domains/"

    # 1. FilePath and Initiation
    VTDomainReputation([String] $path, [string] $apiKey) {
        Clear-Host
        $this.filePath = $path
        $this.listOfDomains = New-Object System.Collections.Generic.List[String]
        $this.responseObj = New-Object System.Collections.Generic.List[PSCustomObject]
        $this.headers.Add("accept", "application/json")
        $this.headers.Add("x-apikey", $apiKey)
    }

    # 2. File Validation
    [bool] isFileValid([String] $filePath) {
        if (!(Test-Path -Path $filePath)) { return $false }
        $this.content = Get-content -path $filePath
        if ($this.content.Length -eq 0) {
            Write-Warning "No data found in the given file"
            return $false
        }
        return $true
    }

    # 3. Domains Extraction
    [void] extractDomains() {
        Write-Host "Extracting Domains"
        foreach ($line in $this.content) {
            $domain = $line.Trim()
            if ($domain -match $this.validator) {
                $this.listOfDomains.Add($domain)
            }
        }
    }

    # 4. Domains Rep Checking
    [void] virusTotalDomainReputation() {
        if (!$this.isFileValid($this.filePath)) {
            Write-Error "Given File $($this.filePath) is Invalid/File Not exist"
            return
        }

        $this.extractDomains()
        Write-Host "$($this.listOfDomains.Count) - Domain(s) found in the file $($this.filePath)"

        if ($this.listOfDomains.Count -eq 0) { return }

        Write-Host "Checking Domains reputation..."
        foreach ($domain in $this.listOfDomains) {
            [String] $finalURL = $this.ENDPOINT + $domain

            try {
                $response = Invoke-WebRequest -Method Get -Uri $finalURL -Headers $this.headers
                if ($response.StatusCode -ne 200) {
                    Write-Host "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)"
                    return;
                }
                $responseData = $response.Content | ConvertFrom-Json
                $CurrentDomain = $responseData.data.id 
                $Harmless = $responseData.data.attributes.last_analysis_stats.harmless
                $Malicious = $responseData.data.attributes.last_analysis_stats.malicious
                $Suspicious = $responseData.data.attributes.last_analysis_stats.suspicious
                $Undetected = $responseData.data.attributes.last_analysis_stats.undetected
                $TotalChecked = $Harmless + $Malicious + $Suspicious + $Undetected

                $obj = [PSCustomObject]@{
                    Domain       = $CurrentDomain
                    Result       = "$Malicious//$TotalChecked"                    
                    TotalChecked = $TotalChecked
                    Harmless     = $Harmless
                    Malicious    = $Malicious
                    Suspicious   = $Suspicious
                    Undetected   = $Undetected
                }
                $this.responseObj.Add($obj)
            }
            catch [System.Net.WebException] {
                Write-Error "Status Code $($_.Exception.Response.StatusCode)"
                Write-Error $($_.Exception.Response)
            }
            catch {
                Write-Error "Something went wrong"
            }

            Write-Host "$($this.responseObj.Count) - Domain(s) checked"
        }
        if (($this.responseObj.Count) -eq 0) { return }
        Write-Host "Completed Checking $($this.responseObj.Count) - Domain(s)"
        
        # Checking Excel is installed or not
        if (!(Test-Path -Path HKLM:\SOFTWARE\Microsoft\Office\*\Excel\)) {
            Write-Host "Excel Application not found"
            Write-Host "Creating CSV File"
            $this.createCSVFile($this.responseObj)
        }
        else {
            Write-Host "Excel Application found"
            $this.createXLFile($this.responseObj)
        }

    }

    [String] getFileName() {
        [String] $fileName = Read-Host  -Prompt "Enter File Name Without Extension"
        return "VT-Domains-Out-File - $fileName"
    }

    # 5. CSV File Creation
    [void] createCSVFile([System.Collections.Generic.List[PSCustomObject]] $data) {
        [String] $fileName = $this.getFileName()
        Write-Host "Creating $fileName.csv file"
        $data | Export-Csv -Path "$fileName.csv" -NoTypeInformation
        Write-Host "Completed creating $fileName.csv" 
    }

    # 6. If supported Create a xlsx file
    [void] createXLFile([System.Collections.Generic.List[PSCustomObject]] $data) {
        $excel = New-Object -ComObject Excel.Application
        [String] $fileName = $this.getFileName()
        try {
            
            $workBook = $excel.Workbooks.Add()
            $sheet = $workBook.Worksheets.Item(1)
            $sheet.Name = "Domains Rep"
        
            $row = 1
            $sheet.Cells.Item($row, 1) = "Domain"
            $sheet.Cells.Item($row, 2) = "Result"
            $sheet.Cells.Item($row, 3) = "TotalChecked"
            $sheet.Cells.Item($row, 4) = "Harmless"
            $sheet.Cells.Item($row, 5) = "Malicious"
            $sheet.Cells.Item($row, 6) = "Suspicious"
            $sheet.Cells.Item($row, 7) = "Undetected"

            $row = 2

            forEach ($obj in $data) {
                $sheet.Cells.Item($row, 1) = $obj.Domain
                $sheet.Cells.Item($row, 2) = $obj.Result
                $sheet.Cells.Item($row, 3) = $obj.TotalChecked
                $sheet.Cells.Item($row, 4) = $obj.Harmless
                $sheet.Cells.Item($row, 5) = $obj.Malicious
                $sheet.Cells.Item($row, 6) = $obj.Suspicious
                $sheet.Cells.Item($row, 7) = $obj.Undetected
                $row++
            }
            Write-Host "Creating $fileName.xlsx file"
            $currentPath = Get-Location
            $completePath = $currentPath.Path + "\$fileName.xlsx"  
            $workBook.SaveAs($completePath)
            $workbook.Close()
            $excel.Quit()
            Write-Host "Completed creating $fileName.xlsx file"   
        }
        finally {
            [int] $exitCode = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel)
            Write-Host "Closed Excel App with status code $exitCode"    
        }
    }   

}


$vtDomainRep = [VTDomainReputation]::new($FilePath, $APIKEY)
$vtDomainRep.virusTotalDomainReputation()