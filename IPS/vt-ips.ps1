[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$FilePath
)
. ..\key.ps1

Clear-Host
$content = Get-content $FilePath
$IPS = New-Object System.Collections.Generic.List[String]
$responseObj = New-Object System.Collections.Generic.List[PSCustomObject]
$API_KEY = $KEY
$headers = @{}
$headers.Add("accept", "application/json")
$headers.Add("x-apikey", $API_KEY)


foreach ($line in $content) {
    $IPS.Add($line)
}


Clear-Host
foreach ($ip in $IPS) {
    $URL = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
    $response = Invoke-WebRequest -Method Get -Uri $URL -Headers $headers
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

    $responseObj.Add($obj)
} 


$responseObj | Export-Csv -Path "vt-out-ips.csv" -NoTypeInformation