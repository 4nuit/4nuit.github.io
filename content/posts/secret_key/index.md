---
title: HackSecuReims - secret key
date: 2023-04-17
author: Nu1t
description: Writeup
tags:
  - misc
---

# Intro

HSR is one of the very first team CTF dedicated to French students. This year, for the 6th edition, there were 150 for the CTF.

Here is a write-up of a cool challenge I solved at [**HackSecuReims**](https://www.hacksecureims.eu/) CTF event last month.

![](./chall_secret-key.png)

We have a somewhat heavy *secret.jpeg* image, the statement tells us that the flag will be located next to a 'passwd' mention.

## Zip Extraction 

So we extract its content:

`binwalk -e secret.png`

We've got a zip, which we try to unzip with 7zip in view of the version, but protected by password:

![](./zip.png)

## 

The first step is to get a hash to work with. I used `zip2john` from John the Ripper to extract a password hash from the zip file:
Here is the pass: **icecream**.
The extracted secret folder reveals a file named *mysecrets.001*:

![](./john.png)

## Disk inspection

The file is actually a logical DOS/MBR disk.
To mount it in a tmp folder, we do a `fdisk -l` in order to know the beginning and the size of each sector.
We use `mount`, but other than pictures of cats, nothing interesting.

![](./mount.png)

## File carving

Fortunately `photorec` can recover deleted files, including this suspicious *.png*:

![](./photorec.png)
![](./recupdir.png)

Here it is!

![](./passwd.png)

