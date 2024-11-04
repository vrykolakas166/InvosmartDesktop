#######################################################
################# COMMAND PARAMETERS #################
#######################################################
param (
    [string]$lv,  # Last version
    [string]$nv   # New version
)

#######################################################
################# FUNCTION DEFINITION #################
#######################################################
function Get-LastVersion {
    param (
        [string]$filePath # version file path to get
    )

    # Check if the specified file exists
    if (Test-Path -Path $filePath) {
        # Read the version string from the file
        $versionString = Get-Content -Path $filePath -ErrorAction Stop

        # Convert the version string to a System.Version object
        try {
            $version = [version]$versionString
            return $version
        } catch {
            Write-Output "Error: The version string in $filePath is not in a valid format."
            return $null
        }
    } else {
        return [version]"0.0.0.0" # edit required
    }
}

function Set-LastVersion {
    param (
        [string]$version, # version value
        [string]$filePath # version file path to get
    )

    # Check if valid
    if ($version -and $filePath) {
        # Set value to file
        Set-Content -Path $filePath -Value $version
    }
}

function Get-LatestVersion {
    # Get the latest folder based on versioning
    $latestFolder = Get-ChildItem -Path $scriptDir -Directory |
        Where-Object { $_.Name -match '^Invosmart_(\d+\.\d+\.\d+\.\d+)_Test$' } |
        Sort-Object {
            # Extract the version part and convert to System.Version
            [version]($_.Name -replace 'Invosmart_|_Test','')
        } -Descending |
        Select-Object -First 1

    # Extract the version string
    if ($latestFolder) {
        $versionString = $latestFolder.Name -replace 'Invosmart_|_Test',''
        return $versionString
    } else {
        Write-Output "No matching folders found."
        return $null
    }
}

#######################################################
######################## MAIN #########################
#######################################################
# Get the directory of the current script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Define the index
$indexFileName = "index.html"
$appinstallerFileName = "Invosmart.appinstaller"

# Construct the full file path
$indexFilePath = Join-Path -Path $scriptDir -ChildPath $indexFileName
$appinstallerFilePath = Join-Path -Path $scriptDir -ChildPath $appinstallerFileName

# Define the path to version.txt
$savedVersionFilePath = Join-Path -Path $scriptDir -ChildPath 'version.txt'

# Check if parameters are provided
if (-not $lv) {
    $lv = Get-LastVersion -filePath $savedVersionFilePath

    # current version is not set
    if("0.0.0.0" -eq $lv){
        Set-LastVersion -version "0.0.0.0" -filePath $savedVersionFilePath
        Write-Output "Please change the current version in version.txt"
        exit
    }
}
if (-not $nv) {
    $nv = Get-LatestVersion
}

# Update version
(Get-Content $indexFilePath) -replace [regex]::Escape($lv), $nv | Set-Content $indexFilePath
(Get-Content $appinstallerFilePath) -replace [regex]::Escape($lv), $nv | Set-Content $appinstallerFilePath

# Remember last version set
Set-LastVersion -version $nv -filePath $savedVersionFilePath

# Notice user
Write-Output "$lv -> $nv"