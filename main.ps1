[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$Name
)
. .\key.ps1

Clear-Host
$content = Get-content $Name
$domains = New-Object System.Collections.Generic.List[String]
$responseStrings = New-Object System.Collections.Generic.List[String]
$API_KEY = $KEY
$headers = @{}
$headers.Add("accept", "application/json")
$headers.Add("x-apikey", $API_KEY)

Set-Content -Value "Domain, TotalChecked, Harmless, Malicious, Suspicious, Undetected" -Path ".\out.csv"

foreach ($line in $content) {
    $domains.Add($line)
}

Clear-Host
foreach ($domain in $domains) {
    $URL = "https://www.virustotal.com/api/v3/domains/$domain"
    $response = Invoke-WebRequest -Method Get -Uri $URL -Headers $headers
    $responseData = $response.Content | ConvertFrom-Json
    $Harmless = $responseData.data.attributes.last_analysis_stats.harmless
    $Malicious = $responseData.data.attributes.last_analysis_stats.malicious
    $Suspicious = $responseData.data.attributes.last_analysis_stats.suspicious
    $Undetected = $responseData.data.attributes.last_analysis_stats.undetected
    $TotalChecked = $Harmless + $Malicious + $Suspicious + $Undetected

    Write-Host "-----------------------------"
    Write-Host "Domain: $Domain"
    Write-Host "Total Checked $TotalChecked"
    Write-Host "Clean $Harmless"
    Write-Host "Malicious: $Malicious"
    Write-Host "Suspicious: $Suspicious"
    Write-Host "Undetected: $Undetected"

    $responseStrings.Add("$Domain, $TotalChecked, $Harmless, $Malicious, $Suspicious, $Undetected")

} 

Write-Host "-----------------------------"
Write-Host "File Created .\out.csv"
Add-Content -Value $responseStrings -Path ".\out.csv"
