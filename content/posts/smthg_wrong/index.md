---
title: FCSC - Quelque chose cloche
date: 2023-05-05
summary: Signature erronnée avec RSA - CRT
author: Nu1t
description: Writeup
tags:
  - crypto
  - writeup
resources:
  - name: "featured-image"
    src: "featured-image.png"
---

## Intro

![](./fcsc.png)

Le FCSC est un CTF de type "jeopardy", avec cette année une soixantaine d'épreuves de difficultés variées dans les catégories suivantes : crypto, reverse, pwn, web, forensics, hardware, attaque par canaux auxiliaires ou en faute et misc. 

La catégorie **Side channel** était particulièrement intéressante car elle proposait ce challenge d'attaque par fautes, ainsi que 2 challenges de défense (voir [**post suivant**](../rsa)).

![](./enonce.png)

## Signature

Voici ce que donne une première connexion au serveur utilisant l'implémentation décrite.

$$s = m^{d}[n]$$ $$m = s^{e}[n]$$

Nous avons à la fin `s` qui sera notée par la suite `s'`: la signature erronée calculée par le serveur.

![](./serv.png)

Nous ne pouvons malheureusement pas **signer m = 1** car cela nous donnerait `dp` et `dq` et on pourrait factoriser n directement.

Le but est de retrouver la **clé privée d** afin de déchiffrer le **ciphertext c**, sachant que la paire ((n,e),d) change à chaque éxécution.

Ainsi, nous pourrons récupérer le flag $$ m = c^{d} [n]$$

## Résolution

Énorme coup de chance, la doc que j'avais cherché pour `RSA - Secure dev` (avec google sur RSA-CRT : iq,dp,dq) donne la solution ...

{{< admonition type=tip title="Théorème de Bezout" open=true >}}
L'algorithme d'Euclide étendu (egcd) permet de trouver les coefficients de [Bezout](https://defeo.lu/in310/poly/euclide-bezout/), tels que

ap + bq = 1
{{< /admonition >}}

D'après l'énoncé nous avons:

{{< raw >}}
\[ cp = m^p[dp] \\  cq = m^q[dq] \\ m = (a*p*cp + b*q*cq) [n]\]
{{< /raw >}}

La signature calculée avec le théorème des **Restes Chinois** (CRT) vaut, avec $$i_{q}= q^{-1} [p]$$

{{< raw >}}
\[ s' = cq +q*(i_{q}*(cp-cq)[p])\]
{{< /raw >}}

{{< admonition type=tip title="RSA et Théorème des Restes Chinois (CRT)" open=true >}}
Le Théorème des Restes Chinois (CRT) est souvent utilisé pour optimiser le déchiffrement RSA en découpant les calculs en sous-problèmes.

**Version Équations Modulaires :**

Dans le contexte de RSA, supposons que nous ayons un message $m$ chiffré $c$ et les modules de chiffrement $N_1, N_2, \ldots, N_k$. Calculons les $M_i$ et les coefficients d'inversion $y_i$ pour chaque $i$ de $1$ à $k$. Ensuite, en utilisant le CRT, la valeur déchiffrée $x$ est donnée par :

$$
m = (c_1 \cdot M_1 \cdot y_1 + c_2 \cdot M_2 \cdot y_2 + \ldots + c_k \cdot M_k \cdot y_k) \ (\mathrm{mod} \ N),
$$

où $N = N_1 \cdot N_2 \cdot \ldots \cdot N_k$.
{{< /admonition >}}


Si vous ne me croyez pas ,c'est dans ce document !

https://www.cosade.org/cosade19/cosade14/presentations/session2_b.pdf

![](./solve.png)

On chiffre donc un message au hasard et on retrouve q avec la seconde méthode.

## Explication:

On dispose de `s'` lorsque le serveur répond: la signature erronée. Notons `s` la vraie signature.

D'où:

$${s'}^{e}[n] - {s}^{e}[n] = {s'}^{e}[n] - m $$

Notons $$\delta = {s'}^{e}[n] - m$$

Nous avons un diviseur commun avec n: $$\delta \wedge n != 1$$

C'est l'attaque de `Bellcore`: https://eprint.iacr.org/2012/553.pdf

## Script

Voici le script qui déroule le tout (~1min)

```python
from Crypto.Util.number import *

c = 8691197749172883783999869319789618890520358126730965200409107370406064006554707505526767161587301532065491886972275903119359532224155354711599130564106144366948103345871831367224426653157094635446381023887990673145477148254742543979935423430776801169055293926445308619472525852943150307661555159608768287631493213019746321573545268091668284963786935853060372774005089483981288875382272937192397700293917020390318315789877283735790900752923209438049279405774089645062273480481195015428987016044959021859352466587859781412088053020118565976357288819878740642165202640596496277942263686968322614760892708394999372377621
m= 3

e = 65537
n = 24092374789898986578319635371648583476600439980337391802703575171857047857157186973589469738598524717467164271258524540616489429272356655174441100779924597091596548506254118920820210014644431581384405741516669846658564893995651994762800981386922622678935264425704567649579129898359460699450083897199747662224532807410886207560447847040297950285025366888583965843432420598518599758119380366544661227909107904202708759769118310010571214615993018135335528945098609588994340874276412541272457264153891261421840299789040416900179377675966523068321023529010524806340701046933963675795872266981575283250285335962694350991853
s = 20109988724347546331933605448539189098587356370928424422747391760423348033837002382899144867015623947899225239174121508108964869874084077980733407484134630342553200036338033461936360491648367626929205539308993531597452037787078623386137499111851588812516907869339483119834320843616385692595133368269569563861312004891486728823683445280930052977845947831259726828558951682588647370285446054725025235049702759513984865144840917884384544713971675994868300767458293324544539118039497009305075085631896683868510719263064259519980588228257267310609908804987070071356193781043867179142394219429108905455352626283232027985695


q = GCD(s**e-m,n)
p = n//q

phi = (p-1)*(q-1)
d = pow(e,-1,phi)

m = pow(c,d,n)
print(long_to_bytes(m))
```

`FCSC{1ec0d4b4c2de4329e2431fb65d229fb7ba2fbf93206e8c273ca22172bdb64d99}`
