#Requires -RunAsAdministrator

$OutputFolder = [Environment]::GetFolderPath('Desktop')
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "`n=== Software History Collector ===`n"

# Create output folder
New-Item -ItemType Directory -Path $OutputFolder -Force -ErrorAction SilentlyContinue | Out-Null

# Get currently installed programs
Write-Host "Getting currently installed programs..."
$regPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$programsFile = Join-Path $OutputFolder "Currently_Installed_Programs_$timestamp.csv"
Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -ne $null } | 
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
    Sort-Object DisplayName | 
    Export-Csv -Path $programsFile -NoTypeInformation -Encoding UTF8
Write-Host "  ✓ Currently installed programs exported to: $programsFile"

# Get MSI installation history
Write-Host "Getting MSI installation history..."
$msiFile = Join-Path $OutputFolder "MSI_Installation_History_$timestamp.csv"
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MsiInstaller'} -ErrorAction SilentlyContinue | 
    Where-Object { $_.Id -in @(1033, 1034, 1035, 1038, 1040, 1042) } | 
    Select-Object TimeCreated, Id, @{N='Product';E={$_.Properties[0].Value}}, @{N='Action';E={
        switch ($_.Id) {
            1033 { 'Install Started' }
            1034 { 'Install Completed' }
            1035 { 'Install Failed' }
            1038 { 'Uninstall Started' }
            1040 { 'Uninstall Completed' }
            1042 { 'Uninstall Failed' }
            default { 'Unknown' }
        }
    }} | 
    Sort-Object TimeCreated | 
    Export-Csv -Path $msiFile -NoTypeInformation -Encoding UTF8
Write-Host "  ✓ MSI installation history exported to: $msiFile"

# Get Windows Update history
Write-Host "Getting Windows Update history..."
$updateFile = Join-Path $OutputFolder "Windows_Update_History_$timestamp.csv"
Get-HotFix -ErrorAction SilentlyContinue | 
    Select-Object HotFixID, Description, InstalledOn, InstalledBy | 
    Sort-Object InstalledOn | 
    Export-Csv -Path $updateFile -NoTypeInformation -Encoding UTF8
Write-Host "  ✓ Windows Update history exported to: $updateFile"

# Get reliability records
Write-Host "Getting reliability records..."
$reliabilityFile = Join-Path $OutputFolder "Reliability_History_$timestamp.csv"
Get-CimInstance -Namespace root\cimv2 -ClassName Win32_ReliabilityRecords -ErrorAction SilentlyContinue | 
    Where-Object { $_.SourceName -in @('Application Install','Application Uninstall','Windows Update') } | 
    Select-Object TimeGenerated, SourceName, ProductName, @{N='EventType';E={
        switch ($_.SourceName) {
            'Application Install' { 'Installation' }
            'Application Uninstall' { 'Uninstallation' }
            'Windows Update' { 'Update' }
            default { 'Unknown' }
        }
    }} | 
    Sort-Object TimeGenerated | 
    Export-Csv -Path $reliabilityFile -NoTypeInformation -Encoding UTF8
Write-Host "  ✓ Reliability records exported to: $reliabilityFile"

# Get Program Inventory log
Write-Host "Getting Program Inventory log..."
$inventoryFile = Join-Path $OutputFolder "Program_Inventory_$timestamp.csv"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Program-Inventory/Operational'} -ErrorAction SilentlyContinue | 
    Where-Object { $_.Id -in @(1001, 1002) } | 
    Select-Object TimeCreated, Id, @{N='Program';E={$_.Properties[0].Value}}, @{N='Action';E={
        switch ($_.Id) {
            1001 { 'Installation' }
            1002 { 'Uninstallation' }
            default { 'Unknown' }
        }
    }} | 
    Sort-Object TimeCreated | 
    Export-Csv -Path $inventoryFile -NoTypeInformation -Encoding UTF8
Write-Host "  ✓ Program Inventory log exported to: $inventoryFile"

# Create zip archive
$csvs = Get-ChildItem -Path $OutputFolder -Filter "*$timestamp.csv"
$zipPath = Join-Path $OutputFolder "Software_History_Report_$timestamp.zip"
Compress-Archive -Path $csvs.FullName -DestinationPath $zipPath -Force -ErrorAction SilentlyContinue
Write-Host "`n✓ Complete report created at: $zipPath"

Write-Host "`nDone!" 