# Hacker Holidays 2026: Day 6 - TryHackMe
### Overheard at Breakfast
"*Two strangers. One conversation. One profile they never meant to reveal.*"

### Overview
Another challenge for OSINT fans. The sixth day of Hacker Holidays 2026!<br>
We are only given a  `.zip` archive. On Linux (or [WSL](https://github.com/lezniakb/Writeups-Guides-Walktroughs/blob/main/Guides/Install%20WSL.md)) use: `unzip overheard-at-breakfast-1784259780309.zip`.

---

### Looking for clues
I checked if there are any clues with Steghide, Exiftool and Binwalk. There are no clues there. We just have to open it..

When you open up the image and read through the conversation, you'll notice one specific thing: Lambo has leaked his email address! It's: `lambobytelotushotel@gmail.com`. He also told us that he had used a service starting with a "G" in the past... 
"G"... Google? Gmail? Github?

Turns out it's [Gravatar](https://gravatar.com/). And they have a website where you can check the email and see the profile: [Gravatar Email Check](https://gravatar.com/site/check)

Just enter: `lambobytelotushotel@gmail.com` and the reward is yours to collect.

<img width="600" alt="image" src="../../Assets/Overheard at Breakfast/pho1.png" />

We can see the Tryhackme Ghost! We KNOW it's the profile we're looking for.

<img width="600" alt="image" src="../../Assets/Overheard at Breakfast/pho2.png" />

Aaaaand that's it, there's the flag. It's just encoded with base64. Simply decode it and enjoy free points

---

### Conclusion
A short OSINT nonetheless. I disliked it. You just have to stumble upon the site that starts with the letter "G" and that's pretty much it. No hidden clues, no alternative paths. That's not how OSINT should look like.

Final flag: `THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}`

---

### Sources
- [Gravatar](https://gravatar.com/)
- [Gravatar Email Check](https://gravatar.com/site/check)
- [Base64 Decoder](https://www.base64decode.org/)
