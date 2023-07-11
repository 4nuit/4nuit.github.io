---
title: "Cheatsheet"
summary: "Quelques ressources pour débuter, from zero to hero"
date: 2023-07-10T22:27:18+02:00
lastmod: 2023-07-10T22:27:18+02:00
description: Notes
author: "Nu1t"
tags: ["active directory", "article", "crypto", "forensic", "misc", "pwn", "reverse", "web"]
resources:
  - name: "featured-image"
    src: "featured-image.png"
---

# Intro

Ce post est un peu spécial. En effet je tenais à partager quelques ressources qui m'ont permis de mettre un pied dans l'infosec en partant de zéro.

Voir: https://github.com/0x14mth3n1ght/Hacking

Est-ce légitime en 2023 de proposer cela? 

Effectivement, il y a pléthore d'articles, de blogs, de livres ainsi que de communautés. 
Mais il est facile de se confronter à un mur et de décourager pour diverses raisons, à tout moment. 

Voici donc un agrégat de ressources:

## Vulgarisation

Des vidéos permettant de découvrir le sujet et de se donner un plan d'attaque.

**Hackintux**:
{{< youtube NuI2xo6v5ko >}}

**Hafnium**:
{{< youtube Q7oMZiiWWek >}}

## Les bases

Juste quelques cours d'informatique générale pour donner une idée.
Ok, sauf pour le web (**OpenClassrooms** peut suffire dans tous les cas)

- Linux: {{< youtube OMaNgQi6Fvc>}}
- Programmation: {{< youtube 90hGCMC3Chc>}}
- Réseau: {{< youtube 26jazyc7VNk>}}
- Web: {{< youtube 4Jk_I-cw4WE>}}

Quelques communautés:

- https://lecrabeinfo.net/ 
- https://openclassrooms.com/fr/courses
- https://zestedesavoir.com/

## Teach yourself infosec

A partir d'ici, la sécurité commence.

https://owasp.org/www-community/attacks/

https://d3fend.mitre.org/

Quelques ressources très complètes ici, par thème.
Pour chaque catégorie, des ressources et plateformes sont données pour s'entraîner.

https://teachyourselfinfosec.com/

Dans la même idée, en français:

https://wiki.zenk-security.com/doku.php/ ou https://www.bases-hacking.org/hacking.html

De très bons livres (dont certains tirés d'OReilly), cours et articles (pas que sur la sécurité) existent aussi ici:

https://doc.lagout.org/


## Mes ressources 

On entre dans le vif du sujet. Maintenant, choisissez la catégorie qui vous plaît et n'hésitez pas à reprendre au point précédent.

## Active Directory

### Bases LDAP

https://www-sop.inria.fr/members/Laurent.Mirtain/ldap-livre.html

### Doc AD:

https://ntlm.info/

https://beta.hackndo.com/pass-the-hash/#protocole-ntlm

https://nuts7.fr/zerologon/

https://zer1t0.gitlab.io/posts/attacking_ad/

### SMB enumeration / Attacking AD

- `enum4linux`

- `impacket` : GetUserSPNs.py pour Kerberoasting par ex

[Box Active (HTB)](https://0xdf.gitlab.io/2018/12/08/htb-active.html)

- `crackmapexec`: https://www.rayanle.cat/write-up-workshop-cme-lehack-2023/

### FreeRDP2

(TryHackMe AD Basics)

```bash
xfreerdp /v:10.10.222.63 /u:THM\Mark /p:M4rk3t1ng.21
```

## Crypto

https://www.youtube.com/@meichlseder

### Doc crypto

- https://cryptobook.nakov.com/
- [20 years of rsa](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf), 
https://vozec.fr/crypto-rsa/ , [Side Channel RSA - RSA CRT cf FCSC](https://www.cosade.org/cosade19/cosade14/presentations/session2_b.pdf)
- https://vozec.fr/crypto-aes/

### Outils

- [Hashes.com](https://hashes.com)
- [Dcode](https://www.dcode.fr/)
- [Cyberchef](https://gchq.github.io/CyberChef/) : Divers encodages/hashs et autres
- [Alpertron](https://www.alpertron.com.ar/ECM.HTM) : RSA (en + de `factordb` et `simpy`)

### Cours: Cryptohack Starters

https://github.com/0x14mth3n1ght/Hacking/tree/main/crypto/elliptic_curves

## Forensic

### Tools:

- `photorec` (récupérer les fichiers supprimés (unlinkés)
- `binwalk` (`binwalk -e <file>` , `binwalk -dd="*" <file>`)
- l'analyse d'une copie de la RAM avec `volatility`:
        - profils linux avec [Vol2 (HackSecuReims)](https://github.com/0x14mth3n1ght/Writeup/tree/master/2023/HackSecuReims/forensic/memdump)

### Analyse de logs

https://github.com/0x14mth3n1ght/Writeup/tree/master/2023/FCSC/forensic/weird_shell

## Pwn

https://gtfobins.github.io/

### Doc :

- Vidéos/Plateformes/Docs: https://mksec.fr/tricks/pwn_ressources/

- Overview du pwn en fr: https://own2pwn.fr 

- [The Shellcoder Handbook](https://doc.lagout.org/security/The%20Shellcoder%E2%80%99s%20Handbook.pdf)

#### Pile/Stack

{{< youtube WG7QtpRPArg>}}

https://thinkloveshare.com/hacking/pwn_1of4_buffer_overflow/

https://ir0nstone.gitbook.io/notes/types/stack

#### Tas/Heap

https://samwho.dev/memory-allocation/

https://heap-exploitation.dhavalkapil.com/attacks/first_fit

https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/

{{< youtube o-nRssrHNMw>}}

{{< youtube PFqEKkj7wWs >}}

https://github.com/shellphish/how2heap


### Débuggers (pour binaires ELF (Linux), plus courants en pwn)

voir `../tutos` (cours/prog C)

- [gdb pour pwn](https://tc.gts3.org/cs6265/2019/tut/tut01-warmup1.html) , pou r la **stack** [gdb-gef](https://github.com/hugsy/gef), pour la **heap** [pwndbg](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md) 


- `r2`: https://github.com/radareorg/radare2

### Arguments et payload

https://reverseengineering.stackexchange.com/questions/13928/managing-inputs-for-payload-injection

### Plateformes

https://deusx64.ai/

https://exploit.education/

https://pwn.college/

https://ropemporium.com/

## Reverse

{{< youtube TUtQcezMDUU >}}

https://www.youtube.com/@StephenChapman

https://m.youtube.com/c/oalabs

### Assembleur x86

https://beta.hackndo.com/assembly-basics/

{{< youtube tmtXn2UXR3g>}}

### Doc reverse:

- https://www.begin.re
- https://tmpout.sh/
- [Plateforme Crackme.one](https://crackmes.one)
- `Awesome Reversing +`:  https://github.com/wtsxDev/reverse-engineering

### Quelques outils:

À posséder:

- En ligne:
	- `Dogbolt (decompiler explorer)`: compare le pseudo code source de différents outils (Ghidra, Hex Rays, Ida, Binary Ninja) rapidement
	- `Disassembler.io`

- `Ghidra` : https://ghidra-sre.org/ (clone d'après les sources du git)

- `UPX unpacker` : https://github.com/NozomiNetworks/upx-recovery-tool

### Windows

Reverse: décompilos:

- `DotPeek` : https://www.jetbrains.com/fr-fr/decompiler/ -> parfait pour du `.NET`
- `DnSpy` : https://github.com/dnSpy/dnSpy -> plus maintenu

### Linux

Outils classiques:

- `objdump`:
	`-t` : afficher la table des symboles -> si rien : voir ../../pwn/asm
	`-h`: afficher les sections

- `ltrace`: voir les fonctions de la libc appelées

- `strace`: voir les syscalls

- `ldd`: voir les bibliothèques/libc utilisées (Hijacking, [ret2libc](../pwn/stack/ret2libc)

Débuggers:

- `gdb`: [gef](https://github.com/hugsy/gef)
- `r2`: https://github.com/radareorg/radare2
- `x64dbg` (windows)

### Bytecode / Outils spécifiques

- Python: `uncompyle`
- Java: `jadx`
- Android: `jadx`, `apktool`, `adb`
- Rust: https://github.com/h311d1n3r/Cerberus
- Unity: https://github.com/imadr/Unity-game-hacking#unity-game-folder-structure

## Web

- [Burp](https://portswigger.net/burp)
- [Jwt_tool](https://github.com/ticarpi/jwt_tool)
- [Beeceptor](https://beeceptor.com/)

### Doc

- https://owasp.org/www-community/Source_Code_Analysis_Tools

- [Payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings)

- [Hacktricks](https://book.hacktricks.xyz/welcome/readme)

- [PayloadBox](https://github.com/payloadbox)

[SQLi: énumération via UNION](https://github.com/0x14mth3n1ght/Writeup/blob/master/2022/Star2022/Web/SQL/sql.txt)
[PHP: extract() & loose comparison](https://github.com/0x14mth3n1ght/Writeup/tree/master/2023/FCSC/web/salty)
[XSS](https://0xhorizon.eu/fr/cheat-sheet/xss/)

## Pour aller plus loin

https://hide01.ir/

https://github.com/akr3ch/BugBountyBooks

[13Cubed](https://www.youtube.com/c/13cubed)

[John Hammond](https://www.youtube.com/channel/UCVeW9qkBjo3zosnqUbG7CFw)

[IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)

[LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w)

[Xct](https://www.youtube.com/c/xct_de/channels)


# Extensions:

https://addons.mozilla.org/fr/firefox/addon/wappalyzer/

https://addons.mozilla.org/en-US/firefox/addon/csp-generator/

https://addons.mozilla.org/fr/firefox/addon/hacktools/

# Des notes utiles en CTF voire +

https://cheatsheet.haax.fr/

https://exploit-notes.hdks.org/

https://notes.vulndev.io/wiki