[Net.ServicePointManager]::SecurityProtocol = "tls12"

# Variables
$TargetHTMFile = "AutomaticSignature"

#==================# Stage Files
# Win32 app runs PowerShell in 32-bit by default. AzureAD module requires PowerShell in 64-bit, so we are going to trigger a rerun in 64-bit.
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    try {
        & "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $PSCommandPath
    }
    catch {
        throw "Failed to start $PSCommandPath"
    }
    exit
}

Start-Transcript -Path "C:\IT\Logs\AutomaticOutlookSignature.txt" -Force -Verbose

# Set Location 
Set-Location $PSScriptRoot


# Install NuGet Package Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope AllUsers -Force

# Install AzureAD module to retrieve the user information
"Installing Azure AD PowerShell Module..."
Install-Module -Name AzureAD -Scope AllUsers -Force -AllowClobber
if ($? -eq $true) {
    "     ...Completed."
}
else {
    "     ERROR - There was an error installing the Azure AD PowerShell Module"
    "     $($Error[0])"
}

# Import Module
"Importing Azure AD PowerShell Module..."
Import-Module -Name AzureAD -Force
if ($? -eq $true) {
    "     ...Completed."
} else {
    "     ERROR - There was an error importing the Azure AD PowerShell Module"
    "     $($Error[0])"
    "     Exiting with Status 1"
    Stop-Transcript
    exit 1
}

# Leverage Single Sign-on to sign into the AzureAD PowerShell module
"Connecting to Azure AD..."
$userPrincipalName = .\whoami.exe -upn
Connect-AzureAD -AccountId $userPrincipalName
if ($? -eq $true) {
    "     ...Completed."
} else {
    "     ERROR - There was an error connecting to Azure AD"
    "     $($Error[0])"
    "     Exiting with Status 1"
    Stop-Transcript
    exit 1
}


# Get the user information to update the signature
$userObject = Get-AzureADUser -ObjectId $userPrincipalName
if ($null -eq $userObject) {
    "     ERROR - There was an error getting the Azure AD user profile."
    "     $($Error[0])"
    "     Exiting with Status 1"
    Stop-Transcript
    exit 1
}

# Create signatures folder if not exists
if (-not (Test-Path "$($env:APPDATA)\Microsoft\Signatures")) {
    $null = New-Item -Path "$($env:APPDATA)\Microsoft\Signatures" -ItemType Directory
}

# Get all signature files
$signatureFiles = Get-ChildItem -Path "$PSScriptRoot\Signatures"
foreach ($signatureFile in $signatureFiles) {
    if ($signatureFile.Name -like "*.htm" -or $signatureFile.Name -like "*.rtf" -or $signatureFile.Name -like "*.txt") {
        # Get file content with placeholder values
        $signatureFileContent = Get-Content -Path $signatureFile.FullName


        <#
        
            USAGE NOTES

            Below contain the strings that will be replaced with the related Azure AD User properties.
            There are also specific formatting included with certain fields, for example:
                %Mobile% has a prefix of "m: " added before the Mobile property is placed.

            Be sure to match the %Property% format of the properties below. If you add them into your email template files they will be replaced by the script.
        
        #>

        # Replace placeholder values
        $signatureFileContent = $signatureFileContent -replace "%DisplayName%", $userObject.DisplayName
        $signatureFileContent = $signatureFileContent -replace "%GivenName%", $userObject.GivenName
        $signatureFileContent = $signatureFileContent -replace "%Surname%", $userObject.Surname
        $signatureFileContent = $signatureFileContent -replace "%Mail%", "e: $($userObject.Mail)"
        if ($userObject.Mobile.Length -gt 4) {
            $signatureFileContent = $signatureFileContent -replace "%Mobile%", "m: $($userObject.Mobile)"
        }
        else {
            $signatureFileContent = $signatureFileContent -replace "%Mobile%", ""
        }
        $signatureFileContent = $signatureFileContent -replace "%TelephoneNumber%", $userObject.TelephoneNumber
        $signatureFileContent = $signatureFileContent -replace "%JobTitle%", $userObject.JobTitle
        $signatureFileContent = $signatureFileContent -replace "%Department%", $userObject.Department
        $signatureFileContent = $signatureFileContent -replace "%City%", $userObject.City
        $signatureFileContent = $signatureFileContent -replace "%Country%", $userObject.Country
        $signatureFileContent = $signatureFileContent -replace "%StreetAddress%", $userObject.StreetAddress
        $signatureFileContent = $signatureFileContent -replace "%PostalCode%", $userObject.PostalCode
        $signatureFileContent = $signatureFileContent -replace "%Country%", $userObject.Country
        $signatureFileContent = $signatureFileContent -replace "%State%", $userObject.State
        $signatureFileContent = $signatureFileContent -replace "%PhysicalDeliveryOfficeName%", $userObject.PhysicalDeliveryOfficeName

        # Set file content with actual values in $env:APPDATA\Microsoft\Signatures
        Set-Content -Path "$($env:APPDATA)\Microsoft\Signatures\$($signatureFile.Name)" -Value $signatureFileContent -Force
    }
    elseif ($signatureFile.getType().Name -eq 'DirectoryInfo') {
        Copy-Item -Path $signatureFile.FullName -Destination "$($env:APPDATA)\Microsoft\Signatures\$($signatureFile.Name)" -Recurse -Force
    }
}

# Final check for target HTM file
if (-not(Test-Path -Path "$($env:APPDATA)\Microsoft\Signatures\$TargetHTMFile.htm")) {
    Stop-Transcript
    "Target HTM file was not found staged in signatures directory. Exiting with status 1."
    exit 1
}


#==================# Set Defaults in Registry
# Variables
#$MyUPN = whoami.exe -upn
$MyUPN = .\whoami.exe -upn
$SearchRegistryPath = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\" 
$NewEmailRegName = "New Signature" 
$ReplayEmailRegValue = "Reply-Forward Signature" 
$RegValue = $TargetHTMFile
$TargetRegPath = ""

# Find Correct Profile Key
$Keys = Get-ChildItem -Path $SearchRegistryPath
$Keys | ForEach-Object {

    $Keys2 = $_ | Get-ChildItem
    $Keys2 | ForEach-Object {

        if (($_ | Get-ItemProperty)."Account Name" -eq $MyUPN) {
            $TargetRegPath = $_.Name
        }
        
    }

}

# Check Target Path was found
if ($TargetRegPath.Length -gt 5) {

    $TargetRegPath_ = $TargetRegPath.Replace("HKEY_CURRENT_USER", "HKCU:")

    try {
        New-ItemProperty `
            -Path $TargetRegPath_ `
            -Name $NewEmailRegName `
            -Value $RegValue `
            -PropertyType String `
            -Force

        New-ItemProperty `
            -Path $TargetRegPath_ `
            -Name $ReplayEmailRegValue `
            -Value $RegValue `
            -PropertyType String `
            -Force 
    }
    catch {

        Stop-Transcript
        "Error - Unable to add Signature Registry keys. Exiting with status 1."
        exit 1

    }

}
else {

    Stop-Transcript
    "Error - Office registry path was not detected. Exiting script with error 1"
    exit 1

}   


# Success Text File Creation
$SignatureTextPath = "C:\IT\SignatureUpdated.txt"
if (-not(Test-Path $SignatureTextPath)) {
    New-Item -Path $SignatureTextPath -Force
}

# Set Content
$UpdatedDate = Get-Date
Set-Content -Path $SignatureTextPath -Value "Last updated: $UpdatedDate"


Stop-Transcript

