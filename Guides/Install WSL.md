Install Kali Linux WSL on Windows 10/11

WSL is Windows Subsystem for Linux. It allows you to use preferred distribution of Linux directly on your system, without the need for a virtual machine

It will take about 20 GB (CHECK IT) from your C: drive

turn windows features

Open up PowerShell in **Administrator** mode.

Update WSL version
```
wsl.exe --update
```

Check which distro you want to Install
```
wsl.exe --list --online
```

We're gonna focus on installing Kali-Linux
```
wsl.exe --install kali-linux
```

Enter your username, password, then retype your password
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

Alright, we've got access! Exit, then enter it again to verify it works
```
wsl.exe -d Kali-Linux
```

Oh, this is a minimal installation and we need to install supplementary tools
```
sudo apt install -y kali-linux-default
```

It should take a while, you download about 10 GB of data. Thankfully this is being installed so fast because it's directly on your SSD (not on a virtual machine drive which is slowwww)

When prompted, select your keyboard configuration. I have selected `Other (at the bottom) -> Polish -> Polish`

Configuring macchanger, I selected `Yes`

Configuring kismet-capture-common, I selected `Yes` and added my username to kismet group

Configuring wireshark, I selected `Yes`

SSLH Configuration: `from inetd`

Wait for the installation to complete.



### Additional packages
```
sudo apt install steghide seclists
```
> steghide is used for steganography and seclists are useful wordlists for pentesting

### Sources
- [How to install Linux on Windows with WSL - learn.microsoft.com](https://learn.microsoft.com/en-us/windows/wsl/install)
