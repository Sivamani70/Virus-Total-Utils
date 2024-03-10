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
        $this.createCSVFile($this.responseObj)

    }
    # 5. CSV File Creation
    [void] createCSVFile([System.Collections.Generic.List[PSCustomObject]] $data) {
        Write-Host "Creating vt-out-domains.csv file"
        $data | Export-Csv -Path "vt-out-domains.csv" -NoTypeInformation
        Write-Host "Completed.!" 
    }

}


$vtDomainRep = [VTDomainReputation]::new($FilePath, $APIKEY)
$vtDomainRep.virusTotalDomainReputation()