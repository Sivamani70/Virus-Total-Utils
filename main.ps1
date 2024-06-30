[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String] $APIKEY,
    [Parameter(Mandatory)]
    [String] $FilePath
)


Class VTReputation{
    [String] $FilePath
    [System.Object[]] $Content
    [Hashtable] $Headers = @{}
    
    [String] $IP_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/"
    [String] $HASH_ENDPOINT = "https://www.virustotal.com/api/v3/files/"
    [String] $DOMAINS_ENDPOINT = "https://www.virustotal.com/api/v3/domains/"

    [String] $MD5_VALIDATOR = "^[a-fA-F0-9]{32}$"
    [String] $SHA1_VALIDATOR = "^[a-fA-F0-9]{40}$"
    [String] $SHA256_VALIDATOR = "^[a-fA-F0-9]{64}$"
    [String] $DOMAINS_VALIDATOR = "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$"   
    [String] $IPV4_VALIDATOR = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    [String] $IPV6_VALIDATOR = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"

    [System.Collections.Generic.HashSet[String]] $Hashes
    [System.Collections.Generic.HashSet[String]] $Domains
    [System.Collections.Generic.HashSet[String]] $IPS

    [System.Collections.Generic.List[PSCustomObject]] $IpResponses
    [System.Collections.Generic.List[PSCustomObject]] $HashResponses
    [System.Collections.Generic.List[PSCustomObject]] $DomainsResponses


    VTReputation([string] $FilePath, [string] $key){
        Clear-Host
        $this.FilePath = $FilePath
        $this.Headers.Add("accept", "application/json")
        $this.Headers.Add("x-apikey", $key)

        $this.Hashes = New-Object System.Collections.Generic.HashSet[String]
        $this.Domains = New-Object System.Collections.Generic.HashSet[String]
        $this.IPS = New-Object System.Collections.Generic.HashSet[String]

        $this.IpResponses = New-Object System.Collections.Generic.List[PSCustomObject]
        $this.HashResponses = New-Object System.Collections.Generic.List[PSCustomObject]
        $this.DomainsResponses = New-Object System.Collections.Generic.List[PSCustomObject]

    }

    [bool] IsFileValid([String] $filePath) {
        if (!(Test-Path -Path $filePath)) { return $false }
        $this.Content = Get-content -path $filePath
        if ($this.content.Length -eq 0) {
            Write-Warning "No data found in the given file"
            return $false
        }
        return $true
    }

    [Void] IOCsExtractor() {
        forEach ($ioc in $this.Content) {
            
            $ioc = ($ioc.ToLower()).Trim()
            
            # Removing Sanitization 
            if ($ioc.Contains("[:]")) {
                $ioc = $ioc.Replace("[:]", ":")
            }

            if ($ioc.Contains("[.]")) {
                $ioc = $ioc.Replace("[.]", ".")
            }

            #IP validation
            if ($ioc -match $this.IPV4_VALIDATOR -or $ioc -match $this.IPV6_VALIDATOR) {
                $this.IPS.Add($ioc) | Out-Null
                Continue;
            }

            #Domains validation
            if ($ioc -match $this.DOMAINS_VALIDATOR) {
                $this.Domains.Add($ioc) | Out-Null
                Continue;
            }


            #MD5 validation
            if ($ioc -match $this.MD5_VALIDATOR -or $ioc -match $this.SHA1_VALIDATOR -or $ioc -match $this.SHA256_VALIDATOR) {
                $this.Hashes.Add($ioc) | Out-Null
                Continue;
            }

        }
        $this.DisplayStatus()
    }

    [Void] DisplayStatus() {
        Write-Host "IOCs From Input" -ForegroundColor Green
        Write-Host "Hashesh: $($this.Hashes.Count)" -ForegroundColor Green
        Write-Host "Domains: $($this.Domains.Count)" -ForegroundColor Green
        Write-Host "IPs: $($this.IPS.Count)" -ForegroundColor Green
    }

    [Void] IPRePCheck(){
        Write-Host "Checking IP reputation..." -ForegroundColor Green
        foreach ($IpAddress in $this.IPS){
            [String] $FinalURL = $this.IP_ENDPOINT + $IpAddress

            try{
                $Response = Invoke-WebRequest -Method Get -Uri $finalURL -Headers $this.Headers
                if ($Response.StatusCode -ne 200) {
                    Write-Host "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)"
                    return;
                }

                $responseData = $Response.Content | ConvertFrom-Json
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

                $this.IpResponses.Add($obj);

            }catch [System.Net.WebException] {
                Write-Error "Status Code $($_.Exception.Response.StatusCode)"
                Write-Error $($_.Exception.Response)
            }

            Write-Host "$($this.IpResponses.Count) - IP(s) checked"

        }
    
    
    }

    [Void] HashRePCheck(){
        Write-Host "Checking Hash values reputation..." -ForegroundColor Green
        foreach ($hash in $this.Hashes){
            $finalURL = $this.HASH_ENDPOINT + $hash

            try{
                $Response = Invoke-WebRequest -Method Get -Uri $finalURL -Headers $this.Headers
                if ($Response.StatusCode -ne 200) {
                    Write-Host "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)" -ForegroundColor Yellow
                    return;
                }

                $responseData = $Response.Content | ConvertFrom-Json
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
                    Result          = "$Malicious//$TotalChecked"
                    TotalChecked    = $TotalChecked
                    Harmless        = $Harmless
                    Malicious       = $Malicious
                    Suspicious      = $Suspicious
                    Undetected      = $Undetected
                }

                $this.HashResponses.Add($obj)

            }catch [System.Net.WebException] {
                Write-Warning "No matches found in VT for: $hash"
                Write-Error "Status $($_.Exception.Response.StatusCode)"
            }catch {
                Write-Error "Something went wrong"
            }

            Write-Host "$($this.HashResponses.Count) - Hash Value(s) checked"
        }
        
    }

    [Void] DomainRePCheck(){
        Write-Host "Checking Domains reputation..." -ForegroundColor Green

        foreach ($domain in $this.Domains){
            [String] $finalURL = $this.DOMAINS_ENDPOINT + $domain

            try{
                $Response = Invoke-WebRequest -Method Get -Uri $finalURL -Headers $this.headers
                if ($Response.StatusCode -ne 200) {
                    Write-Host "Something went wrong;  Status Code: $($response.StatusCode), Status Description: $($response.StatusDescription)"
                    return;
                }
                $responseData = $Response.Content | ConvertFrom-Json
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
                $this.DomainsResponses.Add($obj)
            
            }catch [System.Net.WebException] {
                Write-Error "Status Code $($_.Exception.Response.StatusCode)"
                Write-Error $($_.Exception.Response)
            }catch {
                Write-Error "Something went wrong"
            }

            Write-Host "$($this.DomainsResponses.Count) - Domain(s) checked"
        
        }

    }

    [String] GetFileName() {
        [String] $FileName = Read-Host  -Prompt "Enter File Name Without Extension"
        return "VT-Out-File - $FileName"
    }

    [void] GenerateFile() {
        [String] $FileName = $this.GetFileName()
        $PathWithFileName = (Get-Location).Path + "\$FileName.xlsx"
        $Excel = New-Object -ComObject Excel.Application 

        try{
            $WorkBook = $Excel.Workbooks.Add()
            Write-Host "Creating File -- $PathWithFileName. `nThis may take some time...." -ForegroundColor Green
            
            if($this.IpResponses.Count -ne 0){
                $WorkSheet = $WorkBook.Worksheets.Add()
                $WorkSheet.Name = "IPs - Rep"
                $Row = 1
                $WorkSheet.Cells.Item($Row, 1) = "IP"
                $WorkSheet.Cells.Item($Row, 2) = "ASNOwner"
                $WorkSheet.Cells.Item($Row, 3) = "Country"
                $WorkSheet.Cells.Item($Row, 4) = "Result"
                $WorkSheet.Cells.Item($Row, 5) = "TotalChecked"
                $WorkSheet.Cells.Item($Row, 6) = "Harmless"
                $WorkSheet.Cells.Item($Row, 7) = "Malicious"
                $WorkSheet.Cells.Item($Row, 8) = "Suspicious"
                $WorkSheet.Cells.Item($Row, 9) = "Undetected"

                $Row = 2

                foreach ($Obj in $this.IpResponses){
                    $WorkSheet.Cells.Item($Row, 1) = $Obj.IP
                    $WorkSheet.Cells.Item($Row, 2) = $Obj.ASNOwner
                    $WorkSheet.Cells.Item($Row, 3) = $Obj.Country
                    $WorkSheet.Cells.Item($Row, 4) = $Obj.Result
                    $WorkSheet.Cells.Item($Row, 5) = $Obj.TotalChecked
                    $WorkSheet.Cells.Item($Row, 6) = $Obj.Harmless
                    $WorkSheet.Cells.Item($Row, 7) = $Obj.Malicious
                    $WorkSheet.Cells.Item($Row, 8) = $Obj.Suspicious
                    $WorkSheet.Cells.Item($Row, 9) = $Obj.Undetected
                    $Row++
                }

                $WorkSheet.Columns("A:Z").AutoFit()
            }

            
            if($this.DomainsResponses.Count -ne 0){
                $WorkSheet = $WorkBook.Worksheets.Add()
                $WorkSheet.Name = "Domains - Rep" 
                $Row = 1
                $WorkSheet.Cells.Item($Row, 1) = "Domain"
                $WorkSheet.Cells.Item($Row, 2) = "Result"
                $WorkSheet.Cells.Item($Row, 3) = "TotalChecked"
                $WorkSheet.Cells.Item($Row, 4) = "Harmless"
                $WorkSheet.Cells.Item($Row, 5) = "Malicious"
                $WorkSheet.Cells.Item($Row, 6) = "Suspicious"
                $WorkSheet.Cells.Item($Row, 7) = "Undetected"

                $Row = 2
                forEach ($Obj in $this.DomainsResponses) {
                    $WorkSheet.Cells.Item($Row, 1) = $Obj.Domain
                    $WorkSheet.Cells.Item($Row, 2) = $Obj.Result
                    $WorkSheet.Cells.Item($Row, 3) = $Obj.TotalChecked
                    $WorkSheet.Cells.Item($Row, 4) = $Obj.Harmless
                    $WorkSheet.Cells.Item($Row, 5) = $Obj.Malicious
                    $WorkSheet.Cells.Item($Row, 6) = $Obj.Suspicious
                    $WorkSheet.Cells.Item($Row, 7) = $Obj.Undetected
                    $Row++
                }
                $WorkSheet.Columns("A:Z").AutoFit()
            }

            if($this.HashResponses.Count -ne 0){
                $WorkSheet = $WorkBook.Worksheets.Add()
                $WorkSheet.Name = "Hash - Rep" 
                $Row = 1

                $WorkSheet.Cells.Item($Row, 1) = "MD5"
                $WorkSheet.Cells.Item($Row, 2) = "SHA1"
                $WorkSheet.Cells.Item($Row, 3) = "SHA256"
                $WorkSheet.Cells.Item($Row, 4) = "FileTag"
                $WorkSheet.Cells.Item($Row, 5) = "FileDescription"
                $WorkSheet.Cells.Item($Row, 6) = "Result"
                $WorkSheet.Cells.Item($Row, 7) = "TotalChecked"
                $WorkSheet.Cells.Item($Row, 8) = "Harmless"
                $WorkSheet.Cells.Item($Row, 9) = "Malicious"
                $WorkSheet.Cells.Item($Row, 10) = "Suspicious"
                $WorkSheet.Cells.Item($Row, 11) = "Undetected"

                $Row = 2
                forEach ($obj in $this.HashResponses) {
                    $WorkSheet.Cells.Item($Row, 1) = $obj.MD5
                    $WorkSheet.Cells.Item($Row, 2) = $obj.SHA1
                    $WorkSheet.Cells.Item($Row, 3) = $obj.SHA256
                    $WorkSheet.Cells.Item($Row, 4) = $obj.FileTag
                    $WorkSheet.Cells.Item($Row, 5) = $obj.FileDescription
                    $WorkSheet.Cells.Item($Row, 6) = $obj.Result
                    $WorkSheet.Cells.Item($Row, 7) = $obj.TotalChecked
                    $WorkSheet.Cells.Item($Row, 8) = $obj.Harmless
                    $WorkSheet.Cells.Item($Row, 9) = $obj.Malicious
                    $WorkSheet.Cells.Item($Row, 10) = $obj.Suspicious
                    $WorkSheet.Cells.Item($Row, 11) = $obj.Undetected
                    $Row++
                }

                $WorkSheet.Columns("A:Z").AutoFit()
            }
            
            $SheetOne = $workbook.Sheets["Sheet1"]
            $SheetOne.Delete()
            Write-Host "Saving & Closing the WorkBook" -ForegroundColor Green
            $WorkBook.SaveAs($PathWithFileName)
            $WorkBook.Close()

        }finally{
            $Excel.Quit()
            $ExitCode = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) 
            Write-Host "Closing the File: [$PathWithFileName] with Exit-Code: $ExitCode" -ForegroundColor Yellow
        }   
        
    }

    [void] VirusTotalReputationCheck(){

        if (!$this.isFileValid($this.filePath)) {
            Write-Error "Given File $($this.filePath) is Invalid/File Not exist"
            return
        }

        $this.IOCsExtractor()

        if($this.Hashes.Count -ne 0){
            $this.HashRePCheck()
        }

        if($this.IPS.Count -ne 0){
            $this.IPRePCheck()
        }

        if($this.Domains.Count -ne 0){
            $this.DomainRePCheck()
        }

        $this.GenerateFile()

    }

}


if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Office\*\Excel")) {
    [VTReputation] $VtRep = New-Object VTReputation -ArgumentList $FilePath, $APIKEY
    $VtRep.VirusTotalReputationCheck()
}else {
    Write-Warning "Excel Application is required to create Excel sheets"
    Write-Error "No Excel Module found in the System`nPlease Install Excel and Retry"
}
