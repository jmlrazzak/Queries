**<ins>HOW TO DO THINGS**

PowerShell alias you may see
rm
del
erase

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

**<ins>**
```

```

**<ins>**
```

```

**<ins>**
```

```

**<ins>**
```

```
