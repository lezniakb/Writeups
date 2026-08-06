# Install Linux WSL (Windows Subsystem for Linux) on Windows 10/11
WSL is Windows Subsystem for Linux. It allows you to use preferred distribution of Linux directly on your system, without the need for a virtual machine.

Size: It will take about 20-27 GB from your C: drive.

### Instruction
1. Open up PowerShell in **Administrator** mode.
2. Update WSL version
```
wsl.exe --update
```
3. Check which distro you want to Install
```
wsl.exe --list --online
```
4. We're gonna focus on installing Kali-Linux
```
wsl.exe --install kali-linux
```
5. Enter your username, password, then retype your password
```
PS C:\Users\User\Downloads> wsl --install kali-linux
Downloading: Kali Linux Rolling
Installing: Kali Linux Rolling
Distribution successfully installed.
...
Enter new UNIX username: kali
New password:
Retype new password:
```

Kali should now be installed!<br>
Exit WSL, then enter it again to verify it works:
```
wsl.exe -d Kali-Linux
```

Remember to update the `apt repository`
```
sudo apt update
```

Oh, this is a minimal installation and we need to install supplementary tools
```
sudo apt install -y kali-linux-default
```
> It should take a while as you download about 10 GB of data. Thankfully this is being installed so fast because it's directly on your SSD (not on a virtual machine drive which is so slowwww)

### Additionals during update
When prompted, select your keyboard configuration. I have selected `Other (at the bottom) -> Polish -> Polish`<br>
Select given answers when prompted:
- `macchanger`, I selected `Yes`,
- `kismet-capture-common`, I selected `Yes` and added my username to kismet group
- `wireshark`, I selected `Yes`
- `SSLH` Configuration: `from inetd`

Wait for the installation to complete.

### Additional packages
```
sudo apt install steghide seclists
```
> steghide is used for steganography and seclists are useful wordlists for pentesting

### Sources
- [How to install Linux on Windows with WSL - learn.microsoft.com](https://learn.microsoft.com/en-us/windows/wsl/install)
