# Hacker Holidays 2026: Day 6 - TryHackMe
### Overheard at Breakfast
"*Two strangers. One conversation. One profile they never meant to reveal.*"

Unzip the archive

there are no clues with steghide, exiftool nor binwalk. We just have to open it...

When you open up the image and read through the conversation, you'll notice one specific thing: Lambo has leaked his email address! It's: `lambobytelotushotel@gmail.com`. He also told us that he had used a service starting with a "G" in the past... 
"G"... Google? Gmail? Github?

Turns out it's Gravatar. And they have a website where you can check the email and see the profile: https://gravatar.com/site/check

Just enter: `lambobytelotushotel@gmail.com`

pho1

We can see the Tryhackme Ghost! We KNOW it's the profile we're looking for.

pho2

Aaaaand that's it, there's the flag. It's just encoded with base64. Simply decode it and enjoy free points

flag: `THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}`

### Sources
- [Gravatar Email Check](https://gravatar.com/site/check)
- [Base64 Decoder](https://www.base64decode.org/)
