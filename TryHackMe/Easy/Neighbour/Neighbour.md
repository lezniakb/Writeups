# Neighbour

"Hi there Neighbourino!"

https://tryhackme.com/room/neighbour

Target IP: 10.114.157.65
Attacker IP: 10.114.87.219

Open up the webpage. Nmap says there is only port 80 with HTTP and port 22 with SSH.

Immediately we're met with login screen. But we don't have credentials! Oh, there's a note to use `Ctrl+U` in order to log in with guest credentials. `Ctrl+U` opens up HTML source code of this login page. On line 34 there is a comment with guest credentials.
(pho1)

login: `guest`
password: `guest`

Logged in. They tell us not to peek inside other users' profiles.. But we are pentesters! We can't resist the urge!

(pho2)

Look at URL. You can see there's a parameter `user=guest`.

> Parameters are variables used by backend application, and are delimited by `?` sign in the URL

What if we change `guest` to `admin`? 

(pho3)

We accessed admin panel. We got the flag. Classic IDOR vulnerability.

flag: `flag{66be95c478473d91a5358f2440c7af1f}`

It's no surprise since the author of this CTF told us `IDOR` room is "*similar content*"...

### Conclusion

### Sources
