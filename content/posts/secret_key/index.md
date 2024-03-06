---
title: HackSecuReims 2023 - secret key
date: 2023-04-17
summary: File Carving
author: Nu1t
description: Writeup
tags: ["forensic","misc"]
categories: ["writeup"]
resources:
  - name: "featured-image"
    src: "featured-image.png"
---

## Intro

![](./hack.png)

HSR est l'un des toutes premiers évènements dédiés aux étudiants français. Cette année, pour la 6ème édition, nous étions 150 pour le CTF.

Voici pour commencer un défi sympa que j'ai eu l'occasion de faire au [**HackSecuReims**](https://www.hacksecureims.eu/).

![](./chall_secret-key.png)

Nous avons une image secret.png un peu lourde, l'énoncé nous dit que le flag se situera à côté d'une mention 'passwd'.

## Extraction zip

On extrait donc son contenu:

`binwalk -e secret.png`

On obtient un zip, qu'on essaie de dézipper avec 7zip au vu de la version, mais protégé par mot de passe:

![](./zip.png)

## Crack avec john

On utilise `zip2john` pour donner à john le hash du mot de passe sous un format qu'il connaît.
On le casse avec john, le mot de passe est **icecream**.
Le dossier secret extrait nous révèle un fichier *mysecrets.001*:

![](./john.png)

## Inspection du disque

Le fichier est en fait un disque logique DOS/MBR.
Pour le monter dans un dossier tmp, on effectue un `fdisk -l` afin de connaître le début et la taille de chaque secteur.
On utilise `mount`, mais à part des photos de chats, rien d'intéressant.

![](./mount.png)

## Récupération de fichiers effacés

En pratique j'avais sauté l'étape précédente.
On peut utiliser `photorec` (paquet testdisk) pour faire du file carving:

![](./photorec.png)

## Flag

Un dossier recupdir apparaît avec une image:

![](./recupdir.png)

C'est le flag!

![](./passwd.png)


