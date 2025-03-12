#!/usr/bin/env pwsh
# Secure File Transfer Configuration Tool

param (
    [Parameter(Mandatory=$false, Position=0)]
    [ValidateSet("setup", "remove", "list")]
    [string]$Operation = "setup",
    
    [Parameter(Mandatory=$false, Position=1)]
    [string]$Hostname
)

# Create the credentials directory if it doesn't exist
$credsDir = Join-Path -Path $PSScriptRoot -ChildPath ".creds"
if (-not (Test-Path -Path $credsDir)) {
    New-Item -Path $credsDir -ItemType Directory | Out-Null
}

# Function to list all configured hosts
function List-SecureTransferConfigs {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "          SECURE FILE TRANSFER CONFIGURATIONS             " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Get all configuration files
    $configFiles = Get-ChildItem -Path $PSScriptRoot -Filter ".*-config.bin" -Hidden
    
    if ($configFiles.Count -eq 0) {
        Write-Host "No configurations found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Configured hosts:" -ForegroundColor Green
    
    foreach ($config in $configFiles) {
        $hostname = $config.Name -replace "^\.", "" -replace "-config\.bin$", ""
        
        # Check if it's the default profile
        $isDefault = $false
        if (Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath ".default-profile")) {
            $defaultHost = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath ".default-profile") -Raw
            $defaultHost = $defaultHost.Trim()
            if ($hostname -eq $defaultHost) {
                $isDefault = $true
            }
        }
        
        # Check if credentials are saved
        $hasSavedCreds = Test-Path -Path (Join-Path -Path $credsDir -ChildPath "$hostname.cred")
        
        Write-Host "  - $hostname" -ForegroundColor Cyan -NoNewline
        if ($isDefault) {
            Write-Host " (DEFAULT)" -ForegroundColor Green -NoNewline
        }
        if ($hasSavedCreds) {
            Write-Host " (AUTOMATED)" -ForegroundColor Magenta -NoNewline
        }
        Write-Host ""
    }
    
    Write-Host "`nUse 'secure-transfer-config.ps1 remove <hostname>' to remove a configuration." -ForegroundColor Yellow
}

# Function to remove configurations
function Remove-SecureTransferConfig {
    param (
        [string]$TargetHost
    )
    
    Write-Host "==========================================================" -ForegroundColor Red
    Write-Host "          REMOVE SECURE TRANSFER CONFIGURATION            " -ForegroundColor Red
    Write-Host "==========================================================" -ForegroundColor Red
    Write-Host ""
    
    # If no specific host is provided, ask if user wants to remove all or select one
    if ([string]::IsNullOrWhiteSpace($TargetHost)) {
        # List available configurations
        $configFiles = Get-ChildItem -Path $PSScriptRoot -Filter ".*-config.bin" -Hidden
        
        if ($configFiles.Count -eq 0) {
            Write-Host "No configurations found to remove." -ForegroundColor Yellow
            return
        }
        
        Write-Host "Available configurations:" -ForegroundColor Cyan
        $hosts = @()
        
        for ($i = 0; $i -lt $configFiles.Count; $i++) {
            $hostname = $configFiles[$i].Name -replace "^\.", "" -replace "-config\.bin$", ""
            $hosts += $hostname
            Write-Host "  $($i+1). $hostname" -ForegroundColor Yellow
        }
        
        Write-Host "  A. ALL CONFIGURATIONS" -ForegroundColor Red
        Write-Host "  X. Cancel" -ForegroundColor Gray
        
        $choice = Read-Host "Enter the number of the configuration to remove, 'A' for all, or 'X' to cancel"
        
        if ($choice -eq "X" -or $choice -eq "x") {
            Write-Host "Operation cancelled." -ForegroundColor Gray
            return
        }
        
        if ($choice -eq "A" -or $choice -eq "a") {
            # Confirm removal of all configurations
            $confirm = Read-Host "Are you sure you want to remove ALL configurations? This cannot be undone. (y/n)"
            if ($confirm -ne "y") {
                Write-Host "Operation cancelled." -ForegroundColor Gray
                return
            }
            
            # Remove all configurations
            foreach ($hostname in $hosts) {
                Remove-SingleConfiguration -Hostname $hostname
            }
            
            # Remove default profile
            if (Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath ".default-profile")) {
                Remove-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath ".default-profile") -Force
                Write-Host "Default profile removed." -ForegroundColor Yellow
            }
            
            Write-Host "All configurations have been removed successfully." -ForegroundColor Green
            return
        }
        
        # Convert choice to integer and validate
        try {
            $index = [int]$choice - 1
            if ($index -lt 0 -or $index -ge $hosts.Count) {
                Write-Host "Invalid selection." -ForegroundColor Red
                return
            }
            
            $TargetHost = $hosts[$index]
        }
        catch {
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
    }
    
    # Confirm removal of specific configuration
    $confirm = Read-Host "Are you sure you want to remove the configuration for '$TargetHost'? This cannot be undone. (y/n)"
    if ($confirm -ne "y") {
        Write-Host "Operation cancelled." -ForegroundColor Gray
        return
    }
    
    # Remove the specific configuration
    Remove-SingleConfiguration -Hostname $TargetHost
    
    # Check if it was the default profile and remove if necessary
    if (Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath ".default-profile")) {
        $defaultHost = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath ".default-profile") -Raw
        $defaultHost = $defaultHost.Trim()
        if ($TargetHost -eq $defaultHost) {
            Remove-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath ".default-profile") -Force
            Write-Host "Default profile removed." -ForegroundColor Yellow
        }
    }
    
    Write-Host "Configuration for '$TargetHost' has been removed successfully." -ForegroundColor Green
}

# Helper function to remove a single configuration
function Remove-SingleConfiguration {
    param (
        [string]$Hostname
    )
    
    # Remove configuration files
    $configPath = Join-Path -Path $PSScriptRoot -ChildPath ".$Hostname-config.bin"
    $keyPath = Join-Path -Path $PSScriptRoot -ChildPath ".$Hostname-key.bin"
    $credPath = Join-Path -Path $credsDir -ChildPath "$Hostname.cred"
    
    if (Test-Path -Path $configPath) {
        Remove-Item -Path $configPath -Force
        Write-Host "Removed config file: $configPath" -ForegroundColor Yellow
    }
    
    if (Test-Path -Path $keyPath) {
        Remove-Item -Path $keyPath -Force
        Write-Host "Removed key file: $keyPath" -ForegroundColor Yellow
    }
    
    if (Test-Path -Path $credPath) {
        Remove-Item -Path $credPath -Force
        Write-Host "Removed credential file: $credPath" -ForegroundColor Yellow
    }
}

# Function to set up a new secure transfer configuration
function Set-SecureTransferConfig {
    Clear-Host
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host "          SECURE FILE TRANSFER CONFIGURATION             " -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This tool creates a secure configuration file for automated transfers" -ForegroundColor Yellow
    Write-Host "The configuration file will be encrypted with a master password" -ForegroundColor Yellow
    Write-Host ""
    
    # Get master password for config encryption
    $masterPass = Read-Host "Enter a master password to encrypt the configuration" -AsSecureString
    $masterPassConfirm = Read-Host "Confirm master password" -AsSecureString
    
    # Compare the secure strings
    $bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($masterPass)
    $bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($masterPassConfirm)
    $masterPassText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr1)
    $masterPassConfirmText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
    
    if ($masterPassText -ne $masterPassConfirmText) {
        Write-Host "Passwords do not match. Please try again." -ForegroundColor Red
        exit 1
    }
    
    # Get SFTP connection parameters
    $config = @{}
    $config.hostname = Read-Host "Enter SFTP server hostname or IP"
    $config.username = Read-Host "Enter SFTP username"
    
    # Get SFTP password with masking but avoid truncation issues
    $securePassword = Read-Host "Enter SFTP password" -AsSecureString
    
    # Use a safer conversion method that works correctly on macOS
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try {
        $config.password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    } 
    finally {
        # Always zero out the pointer for security
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
    
    # Get default encryption key
    $config.encryptionKey = Read-Host "Enter default encryption key for file transfers"
    
    # Get default paths
    $config.localUploadPath = Read-Host "Enter default local upload directory path (blank for current directory)"
    if ([string]::IsNullOrEmpty($config.localUploadPath)) {
        $config.localUploadPath = (Get-Location).Path
    }
    
    $config.localDownloadPath = Read-Host "Enter default local download directory path (blank for current directory)"
    if ([string]::IsNullOrEmpty($config.localDownloadPath)) {
        $config.localDownloadPath = (Get-Location).Path
    }
    
    $config.remoteUploadPath = Read-Host "Enter default remote upload path (blank for home directory)"
    if ([string]::IsNullOrEmpty($config.remoteUploadPath)) {
        $config.remoteUploadPath = "~"
    }
    
    $config.remoteDownloadPath = Read-Host "Enter default remote download path (blank for home directory)"
    if ([string]::IsNullOrEmpty($config.remoteDownloadPath)) {
        $config.remoteDownloadPath = "~"
    }
    
    # Convert config to JSON
    $configJson = $config | ConvertTo-Json
    
    # Generate a unique key file name based on hostname
    $keyFilePath = Join-Path -Path $PSScriptRoot -ChildPath ".$($config.hostname)-key.bin"
    
    # Create a random AES key and save it (encrypted with the master password)
    $aesKey = New-Object byte[] 32
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($aesKey)
    
    # Create salt for key derivation
    $salt = New-Object byte[] 16
    $rng.GetBytes($salt)
    
    # Derive key from master password
    $masterPassBytes = [System.Text.Encoding]::UTF8.GetBytes($masterPassText)
    $keyGenerator = New-Object Security.Cryptography.Rfc2898DeriveBytes($masterPassBytes, $salt, 10000)
    $masterKey = $keyGenerator.GetBytes(32)
    
    # Encrypt the AES key with the master key
    $aes = New-Object Security.Cryptography.AesManaged
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.BlockSize = 128
    $aes.KeySize = 256
    $aes.Key = $masterKey
    $aes.GenerateIV()
    
    # Create memory stream to store encrypted key
    $memoryStream = New-Object IO.MemoryStream
    
    # Write salt and IV first (before creating the crypto stream)
    $memoryStream.Write($salt, 0, $salt.Length)
    $memoryStream.Write($aes.IV, 0, $aes.IV.Length)
    
    $cryptoStream = New-Object Security.Cryptography.CryptoStream(
        $memoryStream, 
        $aes.CreateEncryptor(), 
        [Security.Cryptography.CryptoStreamMode]::Write
    )
    
    # Encrypt the AES key
    $cryptoStream.Write($aesKey, 0, $aesKey.Length)
    $cryptoStream.FlushFinalBlock()
    
    # Save the encrypted key
    [System.IO.File]::WriteAllBytes($keyFilePath, $memoryStream.ToArray())
    
    # Clean up encryption resources
    $cryptoStream.Close()
    $memoryStream.Close()
    $aes.Clear()
    
    # Now encrypt the config with the AES key
    $configPath = Join-Path -Path $PSScriptRoot -ChildPath ".$($config.hostname)-config.bin"
    
    $aes = New-Object Security.Cryptography.AesManaged
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.BlockSize = 128
    $aes.KeySize = 256
    $aes.Key = $aesKey
    $aes.GenerateIV()
    
    # Create memory stream to store encrypted config
    $memoryStream = New-Object IO.MemoryStream
    
    # Write IV first (before creating the crypto stream)
    $memoryStream.Write($aes.IV, 0, $aes.IV.Length)
    
    $cryptoStream = New-Object Security.Cryptography.CryptoStream(
        $memoryStream, 
        $aes.CreateEncryptor(), 
        [Security.Cryptography.CryptoStreamMode]::Write
    )
    
    # Encrypt the config
    $configBytes = [System.Text.Encoding]::UTF8.GetBytes($configJson)
    $cryptoStream.Write($configBytes, 0, $configBytes.Length)
    $cryptoStream.FlushFinalBlock()
    
    # Save the encrypted config
    [System.IO.File]::WriteAllBytes($configPath, $memoryStream.ToArray())
    
    # Clean up
    $cryptoStream.Close()
    $memoryStream.Close()
    $aes.Clear()
    
    # Create a default profile file
    $defaultProfile = Join-Path -Path $PSScriptRoot -ChildPath ".default-profile"
    $config.hostname | Set-Content -Path $defaultProfile
    
    # Create credentials directory if it doesn't exist
    $credsDir = Join-Path -Path $PSScriptRoot -ChildPath ".creds"
    if (-not (Test-Path $credsDir)) {
        New-Item -ItemType Directory -Path $credsDir -Force | Out-Null
    }
    
    # Provide instructions
    Write-Host ""
    Write-Host "Configuration saved securely:" -ForegroundColor Green
    Write-Host "- Config file: $configPath" -ForegroundColor Green
    Write-Host "- Key file: $keyFilePath" -ForegroundColor Green
    Write-Host "- Default profile: $defaultProfile" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT: Remember your master password!" -ForegroundColor Yellow
    Write-Host "You will need it to decrypt the configuration when running transfers." -ForegroundColor Yellow
    Write-Host ""
    
    # Ask if the user wants to save the master password for automated operation
    $saveMasterPass = Read-Host "Do you want to save your master password to enable fully automated transfers? (y/n)"
    
    if ($saveMasterPass -eq 'y' -or $saveMasterPass -eq 'Y') {
        # Create the credential and save it
        Write-Host "Saving master password securely..." -ForegroundColor Cyan
        
        # Save to a secure file in the script directory
        $credPath = Join-Path -Path $credsDir -ChildPath "$($config.hostname).cred"
        
        # Create a credential object with the master password
        $securePassword = ConvertTo-SecureString $masterPassText -AsPlainText -Force
        [PSCredential]::new("SecureTransfer-$($config.hostname)", $securePassword) | 
            Export-Clixml -Path $credPath -Force
        
        Write-Host "Master password saved to secure credential store." -ForegroundColor Green
        Write-Host "Credential file: $credPath" -ForegroundColor Green
        Write-Host "You can now use secure-transfer.ps1 with full automation." -ForegroundColor Green
    } else {
        Write-Host "Master password not saved. You will be prompted for it during transfers." -ForegroundColor Yellow
        Write-Host "If you want to enable automation later, run the secure-transfer-config.ps1 script again." -ForegroundColor Yellow
    }
}

# Run the configuration function based on the operation
if ($Operation -eq "setup") {
    Set-SecureTransferConfig
} elseif ($Operation -eq "remove") {
    Remove-SecureTransferConfig -TargetHost $Hostname
} elseif ($Operation -eq "list") {
    List-SecureTransferConfigs
}