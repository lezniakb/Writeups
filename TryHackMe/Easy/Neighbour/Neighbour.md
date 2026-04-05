# Neighbour

"Hi there Neighbourino!"

https://tryhackme.com/room/neighbour

Target IP: 10.114.157.65
Attacker IP: 10.114.87.219

Open up the webpage. Nmap says there is only port 80 with HTTP and port 22 with SSH.

Immediately we're met with login screen. But we don't have credentials! Oh, there's a note to use `Ctrl+U` in order to log in with guest credentials. `Ctrl+U` opens up HTML source code of this login page. On line 34 there is a comment with guest credentials.

<img width="1000" height="191" alt="pho1" src="https://github.com/user-attachments/assets/4dcd48a6-d16e-4f3d-b4b5-10e1ab64143f" />

login: `guest`
password: `guest`

Logged in. They tell us not to peek inside other users' profiles.. But we are pentesters! We can't resist the urge!

<img width="1000" height="312" alt="pho2" src="https://github.com/user-attachments/assets/7a02b204-64cb-4f54-a21f-89f80897089c" />

Look at URL. You can see there's a parameter `user=guest`.

> Parameters are variables used by backend application, and are delimited by `?` sign in the URL

What if we change `guest` to `admin`? 

<img width="1000" height="334" alt="pho3" src="https://github.com/user-attachments/assets/86641c27-0f0b-4905-9bff-dad57e0d774c" />

We accessed admin panel. We got the flag. Classic IDOR vulnerability.

flag: `flag{66be95c478473d91a5358f2440c7af1f}`

It's no surprise since the author of this CTF told us `IDOR` room is "*similar content*"...

### Conclusion

### Sources
