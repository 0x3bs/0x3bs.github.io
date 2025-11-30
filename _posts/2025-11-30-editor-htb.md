---
title: Editor HTB
date: 2025-11-30
categories: [Hack-The-Box]
tags: [CVEs, HTB, PrivEsc]
author: 0x3bs
---

> ### Quick Navigation
> - [Enumeration](#enumeration)
> - [Exploitation](#exploitation)
> - [SSH Creds](#ssh-credentials)
> - [Privilege Escalation](#privilege-escalation)
  

# Enumeration

  
first start with `nmap` :


```bash

┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/htb/Editor]

└─# cat nmap.txt                                            

# Nmap 7.95 scan initiated Sat Nov 29 10:58:00 2025 as: /usr/lib/nmap/nmap -sV -sC -o nmap.txt 10.10.11.80

Nmap scan report for 10.10.11.80

Host is up (0.29s latency).

Not shown: 997 closed tcp ports (reset)

PORT     STATE SERVICE VERSION

22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey:

|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)

|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)

80/tcp   open  http    nginx 1.18.0 (Ubuntu)

|_http-server-header: nginx/1.18.0 (Ubuntu)

|_http-title: Did not follow redirect to http://editor.htb/

8080/tcp open  http    Jetty 10.0.20

|_http-server-header: Jetty(10.0.20)

| http-title: XWiki - Main - Intro

|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/

| http-robots.txt: 50 disallowed entries (15 shown)

| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/

| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/

| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/

| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/

| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/

|_/xwiki/bin/undelete/

| http-cookie-flags:

|   /:

|     JSESSIONID:

|_      httponly flag not set

|_http-open-proxy: Proxy might be redirecting requests

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat Nov 29 10:59:34 2025 -- 1 IP address (1 host up) scanned in 94.89 seconds

  

```

I noticed  that there is open ports :  `22/tcp` , `80/tcp` And `8080/tcp` which was the interesting one 👀

we need to add the domain to `/etc/hosts`

  

```bash

┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/htb/Editor]

└─# cat /etc/hosts  

127.0.0.1       localhost

127.0.1.1       kali

::1             localhost ip6-localhost ip6-loopback

ff02::1         ip6-allnodes

ff02::2         ip6-allrouters

10.10.11.80     editor.htb

```

OK now let's check `http://editor.htb:8080`

  

![](/assets/images/editor/1.png)

  

After search about this version , i found this CVE

  

[CVE-2025-24893](https://github.com/gunzf0x/CVE-2025-24893)

