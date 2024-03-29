[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String] $APIKEY,
    [Parameter(Mandatory)]
    [String] $FilePath
)

class VTHashReputation {
    [String] $FilePath
    [System.Collections.Generic.List[String]] $ListOfHashes
    [System.Collections.Generic.List[PSCustomObject]] $ResponseObj
    [System.Object[]] $Content
    [Hashtable] $Headers = @{}
    [String]$ENDPOINT = "https://www.virustotal.com/api/v3/files/"
    Static [String] $MD5_Validator = "^[a-fA-F0-9]{32}$"
    Static [String] $SHA1_Validator = "^[a-fA-F0-9]{40}$"
    Static [String] $SHA256_Validator = "^[a-fA-F0-9]{64}$"

    #1. FilePath and Initiation of headers
    VTHashReputation([String]$path, [String]$apiKey) {
        $this.FilePath = $path
        $this.ListOfHashes = New-Object System.Collections.Generic.List[String]    
        $this.ResponseObj = New-Object System.Collections.Generic.List[PSCustomObject]    

        $this.Headers.Add("accept", "application/json")
        $this.Headers.Add("x-apikey", $apiKey)
    }   

    #2. File Validation
    [bool] IsFileValid([String] $filePath) {
        if (!(Test-Path -Path $filePath)) { return $false }
        $this.Content = Get-content -path $filePath
        if ($this.Content.Length -eq 0) {
            Write-Warning "No data found in the given file"
            return $false
        }
        return $true
    }

    #3. Hash Extraction
    [void] ExtractHashes() {
        Write-Host "Extracting Hash values"
        foreach ($line in $this.Content) {
            $hash = $line.Trim()
            if ($hash -match [VTHashReputation]::MD5_Validator -or 
                $hash -match [VTHashReputation]::SHA1_Validator -or 
                $hash -match [VTHashReputation]::SHA256_Validator) {
                $this.ListOfHashes.Add($hash)
            }
        }
    }

    #TODO: 4. Hash Rep Checking
    [void] VirusTotalHashReputation() {
        Clear-Host
        if (!$this.IsFileValid($this.FilePath)) {
            Write-Error "Given File $($this.FilePath) is Invalid/File Not exist"
            return
        }

        $this.ExtractHashes()
        Write-Host "$($this.ListOfHashes.Count) - Hash value(s) found in the file $($this.FilePath)"

        if ($this.ListOfHashes.Count -eq 0) { return }
        Write-Host "Checking Hash values reputation..."

        foreach ($hash in $this.ListOfHashes) {
            $finalURL = $this.ENDPOINT + $hash

            try {
                $response = Invoke-WebRequest -Method Get -Uri $finalURL -Headers $this.Headers
                if ($response.StatusCode -ne 200) {
                    Write-Host "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)" -ForegroundColor Yellow
                    return;
                }
                $responseData = $response.Content | ConvertFrom-Json
                $MD5 = $responseData.data.attributes.md5                
                $SHA1 = $responseData.data.attributes.sha1                
                $SHA256 = $responseData.data.attributes.sha256                
                $FileTag = $responseData.data.attributes.type_tag                
                $TypeDescription = $responseData.data.attributes.type_description                
                $Malicious = $responseData.data.attributes.last_analysis_stats.malicious                
                $Suspicious = $responseData.data.attributes.last_analysis_stats.suspicious                
                $Undetected = $responseData.data.attributes.last_analysis_stats.undetected                
                $Harmless = $responseData.data.attributes.last_analysis_stats.harmless                
                $TotalChecked = $Harmless + $Malicious + $Suspicious + $Undetected

                $obj = [PSCustomObject]@{
                    MD5             = $MD5
                    SHA1            = $SHA1
                    SHA256          = $SHA256
                    FileTag         = $FileTag
                    FileDescription = $TypeDescription
                    TotalChecked    = $TotalChecked
                    Harmless        = $Harmless
                    Malicious       = $Malicious
                    Suspicious      = $Suspicious
                    Undetected      = $Undetected
                }
                $this.ResponseObj.Add($obj)
            }
            catch [System.Net.WebException] {
                Write-Error "Status Code $($_.Exception.Response.StatusCode)"
                Write-Error $($_.Exception.Response)
            }
            catch {
                Write-Error "Something went wrong"
            }

            Write-Host "$($this.ResponseObj.Count) - Hash Value(s) checked"
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
    #TODO: 5. CSV Creation
    #TODO: 6. If supported create Excel
}


$vtHashRep = [VTHashReputation]::new($FilePath, $APIKEY)
$vtHashRep.VirusTotalHashReputation()