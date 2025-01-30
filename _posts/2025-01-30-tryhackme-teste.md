---
title: 'TryHackMe: Umbrella'
author: Vitorx
categories: [TryHackMe]
tags: [web, node, docker, mysql, rce]
render_with_liquid: false
---

Umbrella had an exposed Docker registry that allowed us to find database credentials. Using these database credentials to connect to the database and dumping the hashes, we were able to crack them and use the cracked password to get a shell via SSH. Upon discovering the container running a web application had a volume mounted from the host, we examined the source code of this web application to discover a RCE vulnerability and used this to get a shell as root inside the container. To abuse the mentioned mounted volume, we created a suid binary inside that volume from the container and run this suid binary from the host to get a shell as root on the host.

![Tryhackme Room Link](room_card.webp){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/umbrella>_

## Initial enumeration

### Nmap Scan

