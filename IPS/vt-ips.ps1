[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String] $APIKEY,
    [Parameter(Mandatory)]
    [String] $FilePath
)

class VTIPReputation {
    [String] $filePath
    [System.Collections.Generic.List[String]] $listOfIPs
    [System.Collections.Generic.List[PSCustomObject]] $responseObj
    [System.Object[]] $content
    [Hashtable] $headers = @{}
    [String] $IPV4Validator = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    [String] $ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/"
  

    # 1. FilePath and Initiation
    VTIPReputation([String] $path, [string] $apiKey) {
        Clear-Host
        $this.filePath = $path
        $this.listOfIPs = New-Object System.Collections.Generic.List[String]
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

    # 3. IPs Extraction
    [void] extractIPs() {
        Write-Host "Extracting IPS"
        foreach ($ip in $this.content) {
            $ip = $ip.Trim()
            if ($ip -match $this.IPV4Validator) {
                $this.listOfIPs.Add($ip)
            }
        }
    }


    # 4. IP Rep Checking
    [void] virusTotalIPReputation() {
        if (!$this.isFileValid($this.filePath)) {
            Write-Error "Given File $($this.filePath) is Invalid/File Not exist"
            return
        }

        $this.extractIPs()
        Write-Host "$($this.listOfIPs.Count) - IP(s) found in the file $($this.filePath)"

        if ($this.listOfIPs.Count -eq 0) { return }

        Write-Host "Checking IP reputation..."
        foreach ($ipAddress in $this.listOfIPs) {
            [String] $finalURL = $this.ENDPOINT + $ipAddress

            try {
                $response = Invoke-WebRequest -Method Get -Uri $finalURL -Headers $this.headers
                if ($response.StatusCode -ne 200) {
                    Write-Host "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)"
                    return;
                }
                $responseData = $response.Content | ConvertFrom-Json
                $CurrentIP = $responseData.data.id 
                $ASNOwner = $responseData.data.attributes.as_owner
                $Country = $responseData.data.attributes.country
                $Harmless = $responseData.data.attributes.last_analysis_stats.harmless
                $Malicious = $responseData.data.attributes.last_analysis_stats.malicious
                $Suspicious = $responseData.data.attributes.last_analysis_stats.suspicious
                $Undetected = $responseData.data.attributes.last_analysis_stats.undetected
                $TotalChecked = $Harmless + $Malicious + $Suspicious + $Undetected

                $obj = [PSCustomObject]@{
                    IP           = $CurrentIP
                    ASNOwner     = $ASNOwner
                    Country      = $Country
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

            Write-Host "$($this.responseObj.Count) - IP(s) checked"
        }
        if (($this.responseObj.Count) -eq 0) { return }
        Write-Host "Completed Checking $($this.responseObj.Count) - IP(s)"

        if (!(Test-Path -Path HKLM:\SOFTWARE\Microsoft\Office\*\Excel\)) {
            Write-Host "Excel Application not found"
            Write-Host "Creating CSV File"
            $this.createCSVFile($this.responseObj)
        }
        else {
            Write-Host "Excel Application found"
            Write-Host "Creating Excel File"
            $this.createXLFile($this.responseObj)
        }
    }

    [String] getFileName() {
        [DateTime] $dateTime = Get-Date
        [String] $timeStamp = "$($dateTime.DateTime)"
        return "VT-IP-Out-File - $timeStamp"
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
            $sheet.Name = "IPs Rep"
        
            $row = 1
            $sheet.Cells.Item($row, 1) = "IP"
            $sheet.Cells.Item($row, 2) = "ASNOwner"
            $sheet.Cells.Item($row, 3) = "Country"
            $sheet.Cells.Item($row, 4) = "Result"
            $sheet.Cells.Item($row, 5) = "TotalChecked"
            $sheet.Cells.Item($row, 6) = "Harmless"
            $sheet.Cells.Item($row, 7) = "Malicious"
            $sheet.Cells.Item($row, 8) = "Suspicious"
            $sheet.Cells.Item($row, 9) = "Undetected"

            $row = 2

            forEach ($obj in $data) {
                $sheet.Cells.Item($row, 1) = $obj.IP
                $sheet.Cells.Item($row, 2) = $obj.ASNOwner
                $sheet.Cells.Item($row, 3) = $obj.Country
                $sheet.Cells.Item($row, 4) = $obj.Result
                $sheet.Cells.Item($row, 5) = $obj.TotalChecked
                $sheet.Cells.Item($row, 6) = $obj.Harmless
                $sheet.Cells.Item($row, 7) = $obj.Malicious
                $sheet.Cells.Item($row, 8) = $obj.Suspicious
                $sheet.Cells.Item($row, 9) = $obj.Undetected
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

$vtIPRep = [VTIPReputation]::new($FilePath, $APIKEY)
$vtIPRep.virusTotalIPReputation()