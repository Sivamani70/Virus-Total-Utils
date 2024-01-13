[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$FilePath
)
. .\key.ps1


Clear-Host
$content = Get-content $FilePath
$IPS = New-Object System.Collections.Generic.List[String]
$responseStrings = New-Object System.Collections.Generic.List[String]
$API_KEY = $KEY
$headers = @{}
$headers.Add("accept", "application/json")
$headers.Add("x-apikey", $API_KEY)

Set-Content -Value "IP, Owner, Country, TotalChecked, Harmless, Malicious, Suspicious, Undetected" -Path ".\out-IPS.csv"

foreach ($line in $content) {
    $IPS.Add($line)
}


Clear-Host
# $inputData = @{}
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

    Write-Host "-----------------------------"
    Write-Host "IP: $CurrentIP"
    Write-Host "Total Checked $TotalChecked"
    Write-Host "Clean $Harmless"
    Write-Host "Malicious: $Malicious"
    Write-Host "Suspicious: $Suspicious"
    Write-Host "Undetected: $Undetected"

    $responseStrings.Add("$CurrentIP, $ASNOwner, $Country, $TotalChecked, $Harmless, $Malicious, $Suspicious, $Undetected")
    # "IP, Owner, Country, TotalChecked, Harmless, Malicious, Suspicious, Undetected"
    # $newData = @{}
    # $newData.Add("IP", $CurrentIP)
    # $newData.Add("Country", $Country)
    # $newData.Add("TotalChecked", $TotalChecked)
    # $newData.Add("Harmless", $Harmless)
    # $newData.Add("Malicious", $Malicious)
    # $newData.Add("Suspicious", $Suspicious)
    # $newData.Add("Undetected", $Undetected)

} 

# Export-Csv -InputObject $inputData -Path "outFile.csv"
Write-Host "-----------------------------"
Write-Host "File Created .\out-IPS.csv"
Add-Content -Value $responseStrings -Path ".\out-IPS.csv"
