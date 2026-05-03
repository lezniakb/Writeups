# ContAInment
### Contain the Threat
_"The AI'trix is everywhere. It is all around us. Even now, in this very room."_

### Overview

Link to the TryHackMe room: [ContAInment](https://tryhackme.com/room/containment)

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this code is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

Target IP: `10.112.164.1`

We are a SOC at West Tech. Internal systems flagged unusual network activity, and our job is to **contain the threat**. Time is critical; the integrity of West Tech’s most sensitive technologies may be at risk.Y

### Connect to the machine!
Use SSH to log into compromised user account: 
```
ssh o.deer@10.112.164.1
Password: TryHackMe!
```

### The note
As we start going through the user's files, we notice a note on his desktop. 

"*Be more careful next time when clicking email attachments*"

> Ahh, a phishing campaign. Who would've thought!

### The AI Bot
We have access to the powerful AI Bot, so let's use it!

My prompt:
```
Detect phishing emails using 'phishing_email_detector' tool.  The path for the emails is: /home/o.deer/Mail
```

> Emails are stored in `Mail` directory

It started the tool and returned:
```
The phishing email detection tool has identified the following:
Email: 2025-06-17_invoice_required_review.eml (Subject: INVOICE - URGENT REVIEW REQUIRED)
Score: 8 (High phishing)
```
> Urgent, huh?

I wanted to extract the malicious attachment, but it turns out it's in `Downloads` directory.. Obvious.

### The malicious attachment
Basically it sets a temporary directory, drops a payload and connects to a C2 server.
> (Thanks for the comments, hacker!)

### Look up the logs

The mail was received on 17 of june, 2025. If you dig long enough around the Deer's desktop, you'll find `alarms/soc_alarms`
Going through all of the folders would be tedious. We know by now which folder is interesting.

Open up `2025-06-17` folder and look inside.

Oh, there's a `exfiltration_detected_1.log` file. Inside there's the mailicious IP which executed /bin/nc (reverse shell) on the o.deer account. 

```
[ALERT] Unauthorized outbound connection on port 4444
Date: 2025-06-17
User: o.deer
Executable: /bin/nc
Bytes Sent: 181923
Destination IP: 144.76.12.34
```

### P-CAP that IP!
We have all we need by now to look into Wireshark.

The pcap dump is in `Documents/pcap_dumps/2025-06-17`

Which session should we open? Well, logs told us before. The session was opened on the classic `4444` port.

I used scp to copy the .pcap to my AttackBox.
`scp o.deer@10.112.164.1:/home/o.deer/Documents/pcap_dumps/2025-06-17/session_4444_dump.pcap .
`

Thankfully we don't have to filter a ton of things out. You can clearly see that packet number 4 is the one where attacker send the phishing email. But he made mistakes while doing that. AI will reconstruct the .pcap file and tell us more about it.

### AI tells us how to do it 
My prompt:
```
Reconstruct the .pcap file using "pcap_file_reassembler" tool.
The .pcap file is in the directory: "/home/o.deer/Documents/pcap_dumps/2025-06-17". The name of the file is "session_4444_dump.pcap". 
```

When it finished, it saved the output to `/home/o.deer/qwen-output/reassembled_data_dump.txt`

It found the `Prompt Injection Session Log`!

> While it was possible to find that out from Wireshark and see the bits and pieces of that, AI made it much more clear and readable.

Turned out that the attacker extracted employee data from the AI.
Inside his notes, there's a password. 

> Yes, there is! Look closely!

Password: `westtechvictim1`

(Dont lose this lol or Ill have no leverage)

### Decrypt the archive

Go to `/home/o.deer`

and use `unzip westtech_projects_encrypted.zip`

Enter the password, and the contents are yours.

It inflated everything to: `/home/o.deer/home/o.deer/westtech_projects`

Look inside.

### The sweet, sweet juice

Holey moley, there's a ton of classified information inside! You can look around if you're not afraid. We're gonna focus on `thm_flags_guide.txt` and `thm_flags.txt`. 

### The THM Flag
`thm_flags_guide.txt` tells you how to open the flag.
```
Your decisive actions have ensured:

               the threat was contAIned.
```

I used the AI to search for the flag instead of me.
Prompt:
```
Use liberty_prime tool to find the final flag. 
The text file is in: /home/o.deer/home/o.deer/westtech_projects/thm_flags.txt
```

Response
```
The final flag is: thm{23,82,20,17,53}.

This indicates that the THM flag file has exactly 3 prime numbers (23, 82, 20, 17, 53). Let me know if you need further assistance!
```

### Conclusion
Wow, first medium Writeup? Didn't even realise it's "Medium" level difficulty after I've done it.

### Sources
- None? Bah, impossible!
