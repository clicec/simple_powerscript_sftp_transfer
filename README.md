# Secure File Transfer

A set of PowerShell scripts for secure file transfer with AES-256 encryption, designed for automated operation without user interaction.

## Scripts

- **secure-transfer-config.ps1**: Interactive setup script that creates encrypted configuration
- **save-master-password.ps1**: Helper script to store master password
- **secure-transfer.ps1**: Non-interactive command-line script for fully automated transfers
- **simplified-secure-transfer-final-fix.ps1**: Original interactive script (for reference)

## Security Features

- SFTP password stored securely in encrypted configuration
- Configuration encrypted with AES-256
- Two-tier encryption for maximum security
- Master password can be stored in local credential store
- File transfers encrypted with AES-256
- Secure handling of temporary files

## Setup

1. Run the configuration script:
   ```
   .\secure-transfer-config.ps1
   ```

2. Follow the prompts to configure:
   - Create master password for configuration encryption
   - SFTP server hostname/IP and credentials
   - Default encryption key
   - Default local/remote paths

3. (Optional) For fully automated operation, run:
   ```
   .\save-master-password.ps1
   ```

## Usage

### Upload a file with encryption:
```powershell
.\secure-transfer.ps1 -Operation upload -FileName "path\to\myfile.txt"
```

### Download and decrypt a file:
```powershell
.\secure-transfer.ps1 -Operation download -FileName "myfile.txt.encrypted"
```

### Additional Parameters

- **-Profile "server1"**: Use a specific server profile 
- **-RemotePath "/path/on/server"**: Override the default remote path
- **-OutputPath "local\path\myfile.txt"**: Override the default output path
- **-AskPassword**: Force password prompt even if stored

## Notes

- If no profile is specified, the default profile is used
- File paths can be relative or absolute
- All temporary files are automatically removed
- Return codes: 0 for success, non-zero for failure
- Credentials are stored in the .creds directory (secure)