[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$FilePath
)
. ..\key.ps1

class VTIPReputation {
    # 0. Req Fields
    [String] $filePath
    [System.Collections.Generic.List[String]] $listOfIPs
    [System.Collections.Generic.List[PSCustomObject]] $responseObj
    [System.Object[]] $content
    [Hashtable] $headers = @{}
    [String] $basicPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    [String] $endPoint = "https://www.virustotal.com/api/v3/ip_addresses/"
  

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
            if ([System.Text.RegularExpressions.Regex]::IsMatch($ip, $this.basicPattern)) {
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
            [String] $finalURL = $this.endPoint + $ipAddress

            try {
                $response = Invoke-WebRequest -Method Get -Uri $finalURL -Headers $this.headers
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
                    Owner        = $ASNOwner
                    Country      = $Country
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
        $this.createCSVFile($this.responseObj)

    }

    # 5. CSV File Creation
    [void] createCSVFile([System.Collections.Generic.List[PSCustomObject]] $data) {
        Write-Host "Creating vt-out-ips.csv file"
        $data | Export-Csv -Path "vt-out-ips.csv" -NoTypeInformation
        Write-Host "Completed.!" 
    }
}

$vtIPRep = [VTIPReputation]::new($FilePath, $KEY)
$vtIPRep.virusTotalIPReputation()