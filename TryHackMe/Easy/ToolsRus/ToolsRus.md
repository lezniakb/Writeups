# ToolsRus
### Welcome to the store!

Today we're going to enumerate a server, gather information along the way, and finally take over the server.

This room is great for beginners. I tried my best to help you with every part of the challenge.
> Please note this guide was orignally created and posted in 2025 [here](https://medium.com/@lightmagician/toolsrus-tryhackme-guide-ee6f5395363b)

> I also wanted it to be posted on TryHackMe writeups page, but they didn't add it. Hence the redactions.

### General Information
Link to the tryhackme room: [https://tryhackme.com/room/toolsrus](https://tryhackme.com/room/toolsrus)

Attack machine IP: 10.10.69.168<br>
Target machine IP: 10.10.200.17

Recommended prerequisities are:
- Nmap: The Basics
- Metasploit module
- Gobuster: The Basics
- Hydra
- Web Enumeration (Nikto examples)

With that, let's begin! Start the machine along with AttackBox (or linux distribution of your preference).

## 1. What directory can you find, that begins with a "g"?
First question already gives us a few hints.<br>First, we are looking for a directory - so we are going to use gobuster. Next, we already know it starts with "g" so we can make the discovery much faster by cutting down our wordlist!

We need the wordlist. Normally we'd use "*directory-list-2.3-medium.txt*" or the *small* version, but filtering the words starting with "g" will cut down the time needed to find the directory, and is a good practice if you have the info we have.

Here's the command for filtering the wordlist:
```
grep "^g" /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt > g_wordlist
```

Using `wc -l {filename}` we can notice that our wordlist went from 218275 lines to just 3558 lines. Quite the difference!

Next we use that wordlist with gobuster. Gobuster is a directory enumeration tool, made with GO language, hence the name.
```
gobuster dir -u http://10.10.200.17 -w g_wordlist
```
We use "*dir*" mode for directory enumeration, *-u* for url and *-w* for wordlist. If *g_wordlist* isn't working in your case, you might be in the wrong folder or you've named the file as something else.

In under one second we get our result! 

(photo1)

I recommend running gobuster second time in background, with full 2.3-medium list. We'll get to it later.

## 2. Whose name can you find from this directory?
That's easy. Just open a browser of your preference, enter the target's IP and add the found subdomain to url.<br>
Notice that your target IP is different than mine.

(pho2)

Wait, what's that? Some employee left a message for [REDACTED]👷 that's accessible by anyone from the web!

## 3. What directory has basic authentication?
Now we get back to gobuster - we're gonna enumerate the whole (accessible) main directory of the site.

For optimized workflow, this step is recommended to do in the background, when you are working on something else.
```
gobuster dir -u http://10.10.200.17 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

After a short while we get the results. Depending on the server's speed, the time of discovering directories can vary. That's why filtering the wordlist is useful if you have any info on the name or type of directory you want to find.

/[REDACTED] (Status: 301)
/[REDACTED] (Status: 401)
/server-status (Status: 403)

These are the directories found by gobuster with *2.3-medium* wordlist. We can see that one of the directories is definitely the one we're looking for.

## 4. What is #####'s password to the protected part of the website?
So what are we going to do now? We don't have the access!<br>
Well, we know the name of one of the employees. It's possible that's his username, and this question supports that. We're using Hydra to access his account! 🐉

(pho3 here)

> This mystical creature is going to help us with ##### account!

```
hydra -l <username> -P /usr/share/wordlists/rockyou.txt 10.10.200.17 http-get /<directory>
```

Once again, let's go over what's going on here. "*-l*" switch is for defining user, "*-P*" is for wordlist (we are using *rockyou.txt*, famous one for CTFs). Next we define IP we are going to attack, method: *http-get*, and the ##### directory with basic authentication.

After a short while we obtain the password. Upon logging in, we are welcomed by rather discouraging page that the service has been moved to a different port. So where is it?

# 5. What other port that serves a webs service is open on the machine?
Time to use Nmap. Let’s start by checking open ports with *-sS* switch (Syn Scan) switch.

```
root# nmap -sS 10.10.200.17
...
PORT     SERVICE
22/tcp   ssh
80/tcp   http
##/tcp   hotline
8009/tcp ajp13
```

We can see that besides *ssh* and *http* services which we should know, there are two other ports with different services. But what are they? We need to dig deeper.

Now we’re gonna use switches "*-A*", along with "*-sC*" on given ports. We don’t do that when scanning all ports, because it would take a lot more of our time.

(pho4)

I’ve marked down the points of interest. We’ve successfully identified the services on discovered ports! So there is another port that also also serves http site using Apache.. We’re gonna use it later. Now we can answer the question.

## 6. What is the name and version of the software running on the port from question 5?
Well, for us that’s easy! Just look at the output. Look for the port from previous question. http-title discovered under that port tells us the answer.

## 7. How many documentation files did Nikto identify?
Time for our favourite alien - Nikto!<br>
Let’s run the following command
```
root# nikto -h 10.10.200.17 -p <port> -root /manager/html -id "<username>:<password>"
```
- Swtich "*-h*" is host,
- "*-p*" is port,
- "*-root*" is folder we want to search,
- and "*-id*" is credentials we need to authenticate with.

Count the entries and enter the answer.

## 8. What is the server version?
This can be answered with Nmap. In fact, you should already have this answer from question 6. Remember http-title? We’re looking for http-server-header. If you’re a long way from that question, here’s how you can retrieve this information.

(pho5)

## 9. What version of Apache-Coyote is this service using?
Both Nikto and Nmap have answered this question before.<br>
Look under "*+ Server*" on Nikto or "*http-server-header*" with Nmap.

## 10. What user did you get a shell as?
So our task is to break into the machine. We know there is ssh service on the server, but #####’s credentials won’t work there. Enter metasploit.

**Metasploit** - very powerful tool for exploiting CVEs.

Start metasploit console using msfconsole command. From now on, we’re working directly from metasploit.<br>
If you accidentaly ctrl+c out of it, just enter the command again, though you’ll have to go through setting it up again.

(pho6)
>Metasploit console, grab a coffee while it’s loading ;)

What are we looking for? Well, play a bit.

We can check the version against multiple CVE databases like exploit-db.<br>
If you’ve just started the console you need few minutes for it to work. Best practice is to wait 5 minutes, grab a cup of coffee, and then come back. Search command should work almost instantly now.

After searching for **the exploit**, many pops up on the screen. If you know what you’re looking for, you can just select the right one. In our case let’s check the descriptions. We can see that "*Tomcat Manager Authenticated Upload Code Execution*" is something that might satisfy us.

If you still can’t find it, search for "*tomcat_mgr_upload*".

Select the exploit by typing "**use X**" where X is the number of the exploit depending on what you’ve searched. If you’ve searched exactly for *tomcat_mgr_upload* enter "**use 0**".

(pho7)

>Selecting the right exploit

Enter "show options" to check what is Required (yes / no)<br>
Set needed options using "*set*" or "*setg*" - which works globally, even after selecting another exploit. Here’s how it should look like. Remember that we have the user (my man #####!) and his password, so the metasploit won’t have to bruteforce it with it’s own dictionaries.

Now we need to adjust the options - select target IP, target port and also fill the user credentials we got before.

If you happened to enter the wrong exploit, just use "back" command. Using "setg {OPTION}" will make it so that the option stays set the same way even after selecting another exploit.

Here is what you need to set in order for exploit to work:

(pho8)

While HttpPassword and HttpUsername is not required by metasploit, it’s crucial to enter it, because that’s how we access the /manager site.

Now simply run the exploit. you can use either "exploit" or "run" command, they do the same thing.

In meterpreter shell drop simple bash shell using command "shell".

At first we don’t know we have bash shell access to the machine, but commands like "pwd" returns "/" which means we’ve successfuly sent and received data.

(pho9)

Who exactly are we? A simple command can tell us that: "whoami".

Woah! At this level already? Cool, flag.txt will be trivial to find and open.

## 11. What flag is found in the root directory?
Simply cd into /root directory and retrieve the flag. Easy peasy!

## Conclusion
Fun room, wasn’t it? We’ve used tools such as Nmap, Gobuster, Hydra, Metasploit Console and Nikto. Do you remember now what they are for?

Thank you for following through, I hope it proved to be useful to you!
