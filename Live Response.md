**<ins>HOW TO DO THINGS**
```
PowerShell alias you may see
rm , 
del , 
erase
```

**<ins>List the available commands**
```
help
```

**<ins>go to a directory**
```
cd
```

**<ins>go back one directory**
```
cd ..
```

**<ins>see all files in directory**
```
ls
```

**<ins>Delete a file**
```
Linux endpoints or macOS endpoints
rm BADFILE.exe

On Windows endpoints, the only supported delete mechanism is:
remediate file "C:\Full\Path\BAD.exe"
```

**<ins>Force delete a file if normal delete does not work**
```
Linux endpoints or macOS endpoints
rm BADFILE.exe -force

for windows
remediate file "C:\Full\Path\BAD.exe" -auto

If the file is locked / running
processes
remediate process <PID>
remediate file "C:\Full\Path\BAD.exe" -auto
```

**<ins>Powershell Delete a folder and everything inside it**
```
Remove-Item "C:\Path\To\Folder" -Recurse

Force delete (ignore Read‑Only / Hidden flags)
Remove-Item "C:\Path\To\FileOrFolder" -Recurse -Force

Prompt for confirmation before deleting
Remove-Item "C:\Path\To\File.txt" -Confirm
```

**<ins>Create the PowerShell script (on your own machine) to delete a folder and all inside**
```
Create the PowerShell script (on your own machine)

Open Notepad (or VS Code).

Paste this script:
===================
param (
    [Parameter(Mandatory=$true)]
    [string]$Path
)

Remove-Item -LiteralPath $Path -Recurse -Force
========================

Save the file as:
remove-folder.ps1

✅ Make sure:
File extension is .ps1
No special characters in the filename (letters, numbers, dash are safe)

2️⃣ Upload the script to the Live Response library
From the Microsoft Defender portal

Go to https://security.microsoft.com

Navigate to:
Settings
→ Endpoints
→ Advanced features

(Ensure Live response is enabled)

Then go to:
Library
→ Live response

Click Upload file

Select remove-folder.ps1


(Optional but recommended)

Add a description like:
Deletes a folder and all contents

Click Confirm

✅ The script is now in the Live Response library

3️⃣ **You can now run it in Live Response**
When connected to a device via Live Response, execute:
PowerShellrun - just run the entire command below as is;

run remove-folder.ps1 -parameters "-Path \"C:\Users\CarlosGarciaSeverich\AppData\Local\Programs\rave-desktop""

This will delete the entire rave-desktop folder and everything inside it.
```

**<ins>Delete multiple files at once using a PowerShell script**
```
do the same steps as "Create the PowerShell script (on your own machine) to delete a folder and all inside" 

powershell script is below to add to Live response Library
Save the file as:
delete-multiple.ps1

===================
param (
    [Parameter(Mandatory=$true)]
    [string]$FolderPath
)

Get-ChildItem -Path $FolderPath -File | Remove-Item -Force
=======================
**You can now run it in Live Response**
When connected to a device via Live Response, execute:
PowerShellrun - just run the entire command below as is;

run delete-multiple.ps1 -parameters "-FolderPath \"C:\Users\CarlosGarciaSeverich\AppData\Local\Programs\rave-desktop""

This will delete the entire rave-desktop folder and everything inside it.
```

**<ins>**
```

```

**<ins>**
```

```
