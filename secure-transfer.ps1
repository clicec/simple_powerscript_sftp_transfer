# Secure File Transfer with AES-256 - Non-Interactive Version
# This script provides secure file transfer with AES-256 encryption
# with no user interaction after launch

param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("upload", "download")]
    [string]$Operation,
    
    [Parameter(Mandatory=$true)]
    [string]$FileName,
    
    [string]$Profile = "",
    [string]$RemotePath = "",
    [string]$OutputPath = "",
    [switch]$AskPassword
)

# Function to get the master password
function Get-MasterPassword {
    param (
        [string]$hostname,
        [bool]$askPassword
    )
    
    # Check local credential store first (script directory)
    $credPath = Join-Path -Path $PSScriptRoot -ChildPath ".creds" | Join-Path -ChildPath "$hostname.cred"
    
    # If credentials are stored and we're not asked to prompt for password
    if ((Test-Path $credPath) -and (-not $askPassword)) {
        try {
            $credential = Import-Clixml -Path $credPath
            Write-Host "Using stored credentials from: $credPath" -ForegroundColor Green
            return $credential.Password
        } catch {
            Write-Host "Stored credentials couldn't be loaded. Falling back to manual entry." -ForegroundColor Yellow
        }
    }

    # Otherwise, prompt for password
    Write-Host "Master password required to decrypt secure configuration." -ForegroundColor Yellow
    $cred = Get-Credential -Message "Enter master password for secure configuration" -UserName "SecureTransfer"
    return $cred.Password
}

# Function to decrypt configuration
function Get-DecryptedConfig {
    param (
        [string]$hostname,
        [System.Security.SecureString]$masterPassword
    )
    
    # Use Join-Path for cross-platform path handling
    $keyFilePath = Join-Path -Path $PSScriptRoot -ChildPath ".$hostname-key.bin"
    $configPath = Join-Path -Path $PSScriptRoot -ChildPath ".$hostname-config.bin"
    
    if (-not (Test-Path -Path $keyFilePath) -or -not (Test-Path -Path $configPath)) {
        Write-Host "Configuration files not found for profile '$hostname'." -ForegroundColor Red
        Write-Host "Key path attempted: $keyFilePath" -ForegroundColor Yellow
        Write-Host "Config path attempted: $configPath" -ForegroundColor Yellow
        Write-Host "Please run secure-transfer-config.ps1 first." -ForegroundColor Red
        exit 1
    }
    
    # Convert secure string to text
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($masterPassword)
    $masterPassText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    
    try {
        # Read the encrypted key file
        $encryptedKeyBytes = [System.IO.File]::ReadAllBytes($keyFilePath)
        
        # Extract salt (first 16 bytes) and IV (next 16 bytes)
        $salt = New-Object byte[] 16
        $iv = New-Object byte[] 16
        [Array]::Copy($encryptedKeyBytes, 0, $salt, 0, 16)
        [Array]::Copy($encryptedKeyBytes, 16, $iv, 0, 16)
        
        # Get the encrypted AES key (the rest of the file)
        $encryptedKeyData = New-Object byte[] ($encryptedKeyBytes.Length - 32)
        [Array]::Copy($encryptedKeyBytes, 32, $encryptedKeyData, 0, $encryptedKeyData.Length)
        
        # Derive key from master password
        $masterPassBytes = [System.Text.Encoding]::UTF8.GetBytes($masterPassText)
        $keyGenerator = New-Object Security.Cryptography.Rfc2898DeriveBytes($masterPassBytes, $salt, 10000)
        $masterKey = $keyGenerator.GetBytes(32)
        
        # Use the AES managed object to decrypt the key
        $aes = New-Object Security.Cryptography.AesManaged
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.BlockSize = 128
        $aes.KeySize = 256
        $aes.Key = $masterKey
        $aes.IV = $iv
        
        # Decrypt the AES key
        $decryptor = $aes.CreateDecryptor()
        $aesKey = $decryptor.TransformFinalBlock($encryptedKeyData, 0, $encryptedKeyData.Length)
        
        # Read the encrypted config file
        $encryptedConfigBytes = [System.IO.File]::ReadAllBytes($configPath)
        
        # Extract IV (first 16 bytes)
        $configIv = New-Object byte[] 16
        [Array]::Copy($encryptedConfigBytes, 0, $configIv, 0, 16)
        
        # Get the encrypted config data (the rest of the file)
        $encryptedConfigData = New-Object byte[] ($encryptedConfigBytes.Length - 16)
        [Array]::Copy($encryptedConfigBytes, 16, $encryptedConfigData, 0, $encryptedConfigData.Length)
        
        # Create a new AES managed object for config decryption
        $aes = New-Object Security.Cryptography.AesManaged
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.BlockSize = 128
        $aes.KeySize = 256
        $aes.Key = $aesKey
        $aes.IV = $configIv
        
        # Decrypt the config data
        $decryptor = $aes.CreateDecryptor()
        $decryptedConfigBytes = $decryptor.TransformFinalBlock($encryptedConfigData, 0, $encryptedConfigData.Length)
        
        # Convert bytes to JSON string
        $configJson = [System.Text.Encoding]::UTF8.GetString($decryptedConfigBytes)
        
        # Convert JSON to object
        $config = $configJson | ConvertFrom-Json
        return $config
    } catch {
        Write-Host "Error decrypting configuration: $_" -ForegroundColor Red
        exit 1
    }
}

# Determine which profile to use
if ([string]::IsNullOrEmpty($Profile)) {
    $defaultProfilePath = Join-Path -Path $PSScriptRoot -ChildPath ".default-profile"
    if (Test-Path $defaultProfilePath) {
        $Profile = Get-Content -Path $defaultProfilePath
    } else {
        Write-Host "No profile specified and no default profile found." -ForegroundColor Red
        Write-Host "Please run secure-transfer-config.ps1 first or specify a profile with -Profile." -ForegroundColor Red
        exit 1
    }
}

# Get master password and decrypt configuration
$masterPassword = Get-MasterPassword -hostname $Profile -askPassword $AskPassword
$config = Get-DecryptedConfig -hostname $Profile -masterPassword $masterPassword

# Set connection parameters from config
$hostname = $config.hostname
$username = $config.username
$password = $config.password

# Function to encrypt and upload a file
function Encrypt-Upload {
    param (
        [string]$SourceFile,
        [string]$DestinationPath,
        [string]$Key,
        [string]$RemoteUser,
        [string]$RemoteHost,
        [string]$RemotePass
    )
    
    Write-Host "ENCRYPT AND UPLOAD: $SourceFile" -ForegroundColor Cyan
    
    # Verify source file exists
    if (-not (Test-Path -Path $SourceFile -PathType Leaf)) {
        Write-Host "File not found: $SourceFile" -ForegroundColor Red
        exit 1
    }
    
    # Create a temporary file
    $tempFile = [System.IO.Path]::GetTempFileName()
    $encryptedFile = "$tempFile.encrypted"
    $sshKeyFile = "$tempFile.key"
    
    try {
        # Read the file content
        $fileContent = [System.IO.File]::ReadAllBytes($SourceFile)
        $fileName = Split-Path -Path $SourceFile -Leaf
        
        # Encrypt the file with AES-256
        Write-Host "Encrypting file with AES-256..." -ForegroundColor Cyan
        
        # Create encryption key from password
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
        $salt = New-Object byte[] 16
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($salt)
        
        # Create key derivation function
        $keyGenerator = New-Object Security.Cryptography.Rfc2898DeriveBytes($passwordBytes, $salt, 10000)
        $keyBytes = $keyGenerator.GetBytes(32) # 256 bits for AES-256
        
        # Create AES algorithm
        $aes = New-Object Security.Cryptography.AesManaged
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.BlockSize = 128
        $aes.KeySize = 256
        $aes.Key = $keyBytes
        $aes.GenerateIV() # Initialization Vector
        
        # Create a memory stream to store encrypted data
        $memoryStream = New-Object IO.MemoryStream
        $memoryStream.Write($salt, 0, $salt.Length)
        $memoryStream.Write($aes.IV, 0, $aes.IV.Length)
        
        $cryptoStream = New-Object Security.Cryptography.CryptoStream(
            $memoryStream, 
            $aes.CreateEncryptor(), 
            [Security.Cryptography.CryptoStreamMode]::Write
        )
        
        # Encrypt content
        $cryptoStream.Write($fileContent, 0, $fileContent.Length)
        $cryptoStream.FlushFinalBlock()
        
        # Write encrypted content to temporary file
        [System.IO.File]::WriteAllBytes($encryptedFile, $memoryStream.ToArray())
        
        # Clean up encryption resources
        $cryptoStream.Close()
        $memoryStream.Close()
        $aes.Clear()
        
        Write-Host "File encrypted successfully." -ForegroundColor Green
        
        # Upload the encrypted file using the same approach as the original script
        Write-Host "Uploading encrypted file..." -ForegroundColor Cyan
        
        # Ensure destination path is set correctly
        if ([string]::IsNullOrEmpty($DestinationPath)) {
            $DestinationPath = $config.remoteUploadPath
        }
        
        # Create target path for the actual file 
        $remoteTarget = if ($DestinationPath -eq "~" -or [string]::IsNullOrEmpty($DestinationPath)) {
            "~/$fileName.encrypted"
        } else {
            "$DestinationPath/$fileName.encrypted"
        }
        
        Write-Host "Attempting upload to $RemoteHost as user $RemoteUser" -ForegroundColor Cyan
        Write-Host "Target path: $remoteTarget" -ForegroundColor Cyan
        
        # Save password to a temporary file for more secure handling with sshpass
        $tempPassFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "sftp_pass_$(Get-Random).txt"
        try {
            # Write password to file without newline to prevent issues
            Set-Content -Path $tempPassFile -Value $RemotePass -NoNewline
            
            # First establish SSH connection with sshpass to cache credentials
            Write-Host "Testing connection to SFTP server..." -ForegroundColor Cyan
            $sshOutput = sshpass -f $tempPassFile ssh -o StrictHostKeyChecking=no "$RemoteUser@$RemoteHost" "pwd" 2>&1
            $sshExitCode = $LASTEXITCODE
            
            if ($sshExitCode -ne 0) {
                Write-Host "SSH connection test failed with exit code: $sshExitCode" -ForegroundColor Red
                Write-Host "Error: $sshOutput" -ForegroundColor Red
                Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
                Write-Host "1. Verify your SFTP credentials are correct" -ForegroundColor Yellow
                Write-Host "2. Ensure the SFTP server is reachable at $RemoteHost" -ForegroundColor Yellow
                Write-Host "3. Check if your account has the necessary permissions" -ForegroundColor Yellow
                exit 1
            }
            
            Write-Host "Connection successful, uploading file..." -ForegroundColor Green
            
            # Now use SCP to upload the file 
            $uploadOutput = sshpass -f $tempPassFile scp -o StrictHostKeyChecking=no $encryptedFile "$RemoteUser@$RemoteHost`:$remoteTarget" 2>&1
            $uploadResult = $LASTEXITCODE
            
            if ($uploadResult -eq 0) {
                Write-Host "File encrypted and uploaded successfully to $remoteTarget" -ForegroundColor Green
            } else {
                Write-Host "Upload failed with exit code: $uploadResult" -ForegroundColor Red
                Write-Host "Upload error: $uploadOutput" -ForegroundColor Red
                
                # Show detailed troubleshooting information
                Write-Host "`nTroubleshooting upload failure:" -ForegroundColor Yellow
                Write-Host "1. Check if destination directory exists: $DestinationPath" -ForegroundColor Yellow
                Write-Host "2. Verify write permissions to the destination directory" -ForegroundColor Yellow
                Write-Host "3. Ensure there's enough disk space on the remote server" -ForegroundColor Yellow
                exit 1
            }
        }
        finally {
            # Always clean up the password file
            if (Test-Path $tempPassFile) {
                Remove-Item -Path $tempPassFile -Force
            }
        }
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        exit 1
    } finally {
        # Clean up temporary files
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $encryptedFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $sshKeyFile -Force -ErrorAction SilentlyContinue
    }
}

# Function to download and decrypt a file
function Download-Decrypt {
    param (
        [string]$RemoteFile,
        [string]$OutputFile,
        [string]$Key,
        [string]$SourcePath,
        [string]$RemoteUser,
        [string]$RemoteHost,
        [string]$RemotePass
    )
    
    Write-Host "DOWNLOAD AND DECRYPT: $RemoteFile" -ForegroundColor Cyan
    
    # Create a temporary file for the download
    $tempFile = [System.IO.Path]::GetTempFileName()
    $encryptedFile = "$tempFile.encrypted"
    
    try {
        # Ensure source path is set correctly
        if ([string]::IsNullOrEmpty($SourcePath)) {
            $SourcePath = $config.remoteDownloadPath
        }
        
        if ([string]::IsNullOrEmpty($OutputFile)) {
            # Extract original file name by removing .encrypted extension
            $originalFileName = $RemoteFile -replace '\.encrypted$', ''
            $OutputFile = Join-Path $config.localDownloadPath $originalFileName
        }
        
        # Create source path
        $remoteSource = "$RemoteUser@$RemoteHost`:$SourcePath/$RemoteFile"
        
        # Download the encrypted file using sshpass
        Write-Host "Downloading encrypted file..." -ForegroundColor Cyan
        $downloadOutput = sshpass -p $RemotePass scp $remoteSource $encryptedFile 2>&1
        $downloadResult = $LASTEXITCODE
        
        if ($downloadResult -ne 0) {
            Write-Host "Download failed with exit code: $downloadResult" -ForegroundColor Red
            Write-Host "Download output: $downloadOutput" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "File downloaded successfully." -ForegroundColor Green
        
        # Decrypt the file with AES-256
        Write-Host "Decrypting file with AES-256..." -ForegroundColor Cyan
        
        # Read encrypted file
        $encryptedBytes = [System.IO.File]::ReadAllBytes($encryptedFile)
        
        # Get salt (first 16 bytes) and IV (next 16 bytes)
        $salt = New-Object byte[] 16
        $iv = New-Object byte[] 16
        [Array]::Copy($encryptedBytes, 0, $salt, 0, 16)
        [Array]::Copy($encryptedBytes, 16, $iv, 0, 16)
        
        # Create encryption key from password
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
        $keyGenerator = New-Object Security.Cryptography.Rfc2898DeriveBytes($passwordBytes, $salt, 10000)
        $keyBytes = $keyGenerator.GetBytes(32) # 256 bits for AES-256
        
        # Create AES algorithm
        $aes = New-Object Security.Cryptography.AesManaged
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.BlockSize = 128
        $aes.KeySize = 256
        $aes.Key = $keyBytes
        $aes.IV = $iv
        
        # Create memory streams in a more explicit way for cross-platform compatibility
        $decryptedStream = New-Object IO.MemoryStream
        $memoryStream = New-Object IO.MemoryStream
        $memoryStream.Write($encryptedBytes, 32, $encryptedBytes.Length - 32)
        $memoryStream.Position = 0  # Reset position to beginning of stream
        
        $cryptoStream = New-Object Security.Cryptography.CryptoStream(
            $memoryStream, 
            $aes.CreateDecryptor(), 
            [Security.Cryptography.CryptoStreamMode]::Read
        )
        
        # Read decrypted bytes
        $buffer = New-Object byte[] 4096
        $bytesRead = $cryptoStream.Read($buffer, 0, $buffer.Length)
        while ($bytesRead -gt 0) {
            $decryptedStream.Write($buffer, 0, $bytesRead)
            $bytesRead = $cryptoStream.Read($buffer, 0, $buffer.Length)
        }
        
        # Write decrypted content to output file
        [System.IO.File]::WriteAllBytes($OutputFile, $decryptedStream.ToArray())
        
        # Clean up decryption resources
        $cryptoStream.Close()
        $memoryStream.Close()
        $decryptedStream.Close()
        $aes.Clear()
        
        Write-Host "File decrypted successfully and saved to $OutputFile" -ForegroundColor Green
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        exit 1
    } finally {
        # Clean up temporary files
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $encryptedFile -Force -ErrorAction SilentlyContinue
    }
}

# Execute the requested operation
switch ($Operation) {
    "upload" {
        # For upload, FileName is the source file
        $sourcePath = $FileName
        if (-not [System.IO.Path]::IsPathRooted($sourcePath)) {
            $sourcePath = Join-Path $config.localUploadPath $FileName
        }
        Encrypt-Upload -SourceFile $sourcePath -DestinationPath $RemotePath -Key $config.encryptionKey -RemoteUser $username -RemoteHost $hostname -RemotePass $password
    }
    "download" {
        # For download, FileName is the remote encrypted file
        Download-Decrypt -RemoteFile $FileName -OutputFile $OutputPath -Key $config.encryptionKey -SourcePath $RemotePath -RemoteUser $username -RemoteHost $hostname -RemotePass $password
    }
}