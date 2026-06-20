# TBU

Target IP: 10.81.167.29
Attackbox IP: 10.81.124.166

root@ip-10-81-124-166:~# nmap -sS 10.81.167.29 -p-
Starting Nmap 7.80 ( https://nmap.org ) at 2026-02-12 16:32 GMT
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.81.167.29
Host is up (0.0047s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  waste

Nmap done: 1 IP address (1 host up) scanned in 3.84 seconds
root@ip-10-81-124-166:~# 


In cookies there is PHPSESSID saved



root@ip-10-81-124-166:~# gobuster dir --url http://10.81.167.29:1337 --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,txt,php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.81.167.29:1337
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 279]
/.php                 (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 1326]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
/vendor               (Status: 301) [Size: 320] [--> http://10.81.167.29:1337/vendor/]
/dashboard.php        (Status: 302) [Size: 0] [--> logout.php]
/phpmyadmin           (Status: 301) [Size: 324] 


w html był komentarz: 
root@ip-10-81-124-166:~# curl -d --url http://10.81.167.29:1337

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/hmr_css/bootstrap.min.css" rel="stylesheet">
	<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->



/hmr_css              (Status: 301) [Size: 321] [--> http://10.81.167.29:1337/hmr_css/]
/hmr_images           (Status: 301) [Size: 324] [--> http://10.81.167.29:1337/hmr_images/]
/hmr_js               (Status: 301) [Size: 320] [--> http://10.81.167.29:1337/hmr_js/]
/hmr_logs             (Status: 301) [Size: 322] [



Logs might interest us!
http://10.81.167.29:1337/hmr_logs/
This folder shows us 
Index of /hmr_logs

Go to
http://10.81.167.29:1337/hmr_logs/error.logs
This log tells us what is one of user logins!

[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] [pid 12347:tid 139999999999997] [client 192.168.1.12:37210] AH01631: user tester@hammer.thm: authentication failure for "/restricted-area": Password Mismatch

[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [pid 12351:tid 139999999999993] [client 192.168.1.30:40232] AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address

It works for /restricted-area but not for /admin-login


Something changed the PHPSESSID: 
PHPSESSID	"ei2pvqicas81hvllkg49l92133"

Login page doesn't tell us if we have good email, but reset_password.php does. 
We can enumerate other logins there if needed, but using tester@hammer.thm creates a recovery code. We then have three minutes to find it and enter it.

recovery_code=1234&s=134

root@ip-10-81-124-166:~# python3 crack3
Success! Recovery Code: 1051
PHPSESSID: 2i8bhiuf17jf9r1p9iafpetlt2

Change PHPSESSID in browser and reset the password (I changed it to 123)

We're getting logged out constantlyyy
Using burp change 