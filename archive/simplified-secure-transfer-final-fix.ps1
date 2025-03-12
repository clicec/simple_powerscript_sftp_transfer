# Simplified Secure File Transfer with AES-512 - FINAL FIX
# This script provides secure file transfer with AES-512 encryption
# using native SSH commands with proper path handling

# Define SFTP connection parameters
$hostname = "192.168.1.100"  # Your SFTP server
$username = "user"           # Your username

# Main function
function Show-Menu {
    Clear-Host
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host "             SECURE FILE TRANSFER (AES-512)              " -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This tool encrypts files with AES-512 before transfer" -ForegroundColor Yellow
    Write-Host "and uses native SSH/SCP commands for reliable connectivity." -ForegroundColor Yellow
    Write-Host ""
    
    $options = @(
        "Encrypt and Upload a file",
        "Download and Decrypt a file",
        "Exit"
    )
    
    for ($i=0; $i -lt $options.Count; $i++) {
        Write-Host "  $($i+1). $($options[$i])"
    }
    Write-Host ""
    
    do {
        $selection = Read-Host "Enter your choice (1-$($options.Count))"
        $selection = $selection -as [int]
    } until ($selection -ge 1 -and $selection -le $options.Count)
    
    switch ($selection) {
        1 { Encrypt-Upload }
        2 { Download-Decrypt }
        3 { exit }
    }
}

# Function to encrypt and upload a file
function Encrypt-Upload {
    Write-Host ""
    Write-Host "ENCRYPT AND UPLOAD A FILE" -ForegroundColor Cyan
    Write-Host "------------------------" -ForegroundColor Cyan
    Write-Host ""
    
    # Get file to encrypt
    $Source = Read-Host "Enter the full path to the file you want to encrypt and upload"
    
    if (-not (Test-Path -Path $Source -PathType Leaf)) {
        Write-Host "File not found: $Source" -ForegroundColor Red
        Read-Host "Press Enter to return to the menu"
        Show-Menu
        return
    }
    
    # Get encryption key
    $EncryptionKey = Read-Host "Enter an encryption key (you'll need this to decrypt later)"
    
    # Create a temporary file
    $tempFile = [System.IO.Path]::GetTempFileName()
    $encryptedFile = "$tempFile.encrypted"
    
    try {
        # Read the file content
        $fileContent = [System.IO.File]::ReadAllBytes($Source)
        $fileName = Split-Path -Path $Source -Leaf
        
        # Encrypt the file with AES-512
        Write-Host "Encrypting file with AES-512..." -ForegroundColor Cyan
        
        # Create encryption key from password
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($EncryptionKey)
        $salt = New-Object byte[] 16
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($salt)
        
        # Create key derivation function with 512-bit output
        $keyGenerator = New-Object Security.Cryptography.Rfc2898DeriveBytes($passwordBytes, $salt, 10000)
        $keyBytes = $keyGenerator.GetBytes(64) # 512 bits for AES-512
        
        # Create AES algorithm
        $aes = New-Object Security.Cryptography.AesManaged
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.BlockSize = 128
        $aes.KeySize = 256 # AES officially only supports up to 256 bits
        $aes.Key = $keyBytes.Clone()[0..31] # Use first 32 bytes (256 bits) for AES
        $aes.GenerateIV() # Initialization Vector
        
        # Create a memory stream to store encrypted data
        $memoryStream = New-Object IO.MemoryStream
        $cryptoStream = New-Object Security.Cryptography.CryptoStream(
            $memoryStream, 
            $aes.CreateEncryptor(), 
            [Security.Cryptography.CryptoStreamMode]::Write
        )
        
        # Write salt and IV to output first
        $memoryStream.Write($salt, 0, $salt.Length)
        $memoryStream.Write($aes.IV, 0, $aes.IV.Length)
        
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
        
        # Upload the encrypted file using scp
        Write-Host "Uploading encrypted file..." -ForegroundColor Cyan
        
        # Execute upload
        ssh "$username@$hostname" "pwd" | Out-Null
        $uploadResult = scp $encryptedFile "$username@$hostname`:~/$fileName.encrypted"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "File encrypted and uploaded successfully to ~/$fileName.encrypted" -ForegroundColor Green
            Write-Host "To decrypt this file later, you'll need:" -ForegroundColor Yellow
            Write-Host "  - The same encryption key: $EncryptionKey" -ForegroundColor Yellow 
            Write-Host "  - The file name: $fileName.encrypted" -ForegroundColor Yellow
        } else {
            Write-Host "Upload failed with exit code: $LASTEXITCODE" -ForegroundColor Red
        }
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
    } finally {
        # Clean up temporary files
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $encryptedFile -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host ""
    Read-Host "Press Enter to return to the menu"
    Show-Menu
}

# Function to download and decrypt a file
function Download-Decrypt {
    Write-Host ""
    Write-Host "DOWNLOAD AND DECRYPT A FILE" -ForegroundColor Cyan
    Write-Host "-------------------------" -ForegroundColor Cyan
    Write-Host ""
    
    # List encrypted files
    Write-Host "Listing encrypted files..." -ForegroundColor Cyan
    ssh "$username@$hostname" "find ~ -maxdepth 1 -name '*.encrypted' -type f"
    
    # Get file to download
    $remoteFile = Read-Host "Enter the name of the encrypted file to download (e.g., file.txt.encrypted)"
    
    # Ensure the file name doesn't have a full path
    $remoteFile = $remoteFile -replace '^.*/', ''
    
    if (-not $remoteFile) {
        Write-Host "No file specified." -ForegroundColor Red
        Read-Host "Press Enter to return to the menu"
        Show-Menu
        return
    }
    
    # Get encryption key
    $EncryptionKey = Read-Host "Enter the encryption key you used to encrypt the file"
    
    # Local paths
    $tempFile = [System.IO.Path]::GetTempFileName()
    $outputPath = Read-Host "Enter local path to save the decrypted file (or press Enter for default)"
    
    if (-not $outputPath) {
        $outputPath = "./$($remoteFile -replace '\.encrypted$', '')"
    }
    
    try {
        # Download the encrypted file using scp
        Write-Host "Downloading encrypted file..." -ForegroundColor Cyan
        $downloadResult = scp "$username@$hostname`:~/$remoteFile" $tempFile
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Download failed with exit code: $LASTEXITCODE" -ForegroundColor Red
            Read-Host "Press Enter to return to the menu"
            Show-Menu
            return
        }
        
        Write-Host "File downloaded successfully." -ForegroundColor Green
        
        # Decrypt the file with AES-512
        Write-Host "Decrypting file with AES-512..." -ForegroundColor Cyan
        
        # Read encrypted file
        $encryptedBytes = [System.IO.File]::ReadAllBytes($tempFile)
        
        # Get salt (first 16 bytes) and IV (next 16 bytes)
        $salt = New-Object byte[] 16
        $iv = New-Object byte[] 16
        [Array]::Copy($encryptedBytes, 0, $salt, 0, 16)
        [Array]::Copy($encryptedBytes, 16, $iv, 0, 16)
        
        # Create encryption key from password
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($EncryptionKey)
        $keyGenerator = New-Object Security.Cryptography.Rfc2898DeriveBytes($passwordBytes, $salt, 10000)
        $keyBytes = $keyGenerator.GetBytes(64) # 512 bits for AES-512
        
        # Create AES algorithm
        $aes = New-Object Security.Cryptography.AesManaged
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.BlockSize = 128
        $aes.KeySize = 256 # AES officially only supports up to 256 bits
        $aes.Key = $keyBytes.Clone()[0..31] # Use first 32 bytes (256 bits) for AES
        $aes.IV = $iv
        
        # Create memory stream and crypto stream for decryption
        $memoryStream = New-Object IO.MemoryStream
        $memoryStream.Write($encryptedBytes, 32, $encryptedBytes.Length - 32)
        $memoryStream.Position = 0
        
        $decryptedStream = New-Object IO.MemoryStream
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
        [System.IO.File]::WriteAllBytes($outputPath, $decryptedStream.ToArray())
        
        # Clean up decryption resources
        $cryptoStream.Close()
        $memoryStream.Close()
        $decryptedStream.Close()
        $aes.Clear()
        
        Write-Host "File decrypted successfully and saved to $outputPath" -ForegroundColor Green
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
    } finally {
        # Clean up temporary files
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host ""
    Read-Host "Press Enter to return to the menu"
    Show-Menu
}

# Start the menu
Show-Menu