---
title: Reverse - BreakThePass
category: Sthack2021
author: karzemrok
tags:
- sthack2021
- reverse
- ctf
description: "Writeup Sthack 2021 - BreakThePass - Reverse"
---
L'application Web est un formulaire qui demande un mot de passe.

![]({{site.url}}/static/upload_6538cf22107f787c3a61175f8c42d0af.png)

La fonction `check_password` en JS est la suivante:

```javascript
function check_password() {
    let input = document.getElementById("chall-input-password");
    if (!input) {
        console.log("L'input n'a pas été trouvé");
        return;
    }
    let _value = input.value
    let ptr = allocate(intArrayFromString(_value), ALLOC_NORMAL);
    _check_the_flag(ptr)
    _free(ptr)
}
```

La valeur du mot de passe est transformée en tableau d'**int** et mise en mémoire.

Le pointeur vers cet espace mémoire est passé en paramètre de '**_check_the_flag**' qui est un alias vers une fonction interne d'un programme wasm.

Nous allons transformer le WASM en JS (avec [wasm2js](https://github.com/WebAssembly/binaryen)) et en WAT (avec [wasm2wat](https://github.com/WebAssembly/wabt)) pour avoir deux vues différentes pour nous simplifier l'analyse du binaire.

```shell
wasm2wat assets/authentification.wasm -o assets/authentification.wat
wasm2js assets/authentification.wasm -o assets/authentification.wasm.js
```

Le format JS est plus lisible, mais le WAT à l'avantage de pouvoir être retransformé en WASM facilement.

Pour qu'une fonction du WASM soit utilisable en JS, il faut qu'elle soit exportée, ce qui va nous aider à l'identifier.

Dans le format WAT, la fonction est la 37

![]({{site.url}}/static/upload_3159d9e239b5f92578061eb7ae19a562.png)

Alors que dans le JS, c'est "**$33**"

![]({{site.url}}/static/upload_02973bb75a849b016bd9292cd2f8e74a.png)

On voit des appels à 3 fonctions différentes:

![]({{site.url}}/static/upload_c258278c77747a7a9bd7e7f45891e022.png)

- fimport$1
- fimport$0
- $4

'**fimport$1**' dans notre cas exécute **gettimeofday**, elle ne sera pas intéressante ici.

La fonction **fimport$0** prend en paramètre un offset dans les data et utilise la chaîne de caractères disponible à cette adresse en tant que paramètre de **emscripten_run_script** qui se charge d'exécuter la chaine de caractère en tant que JavaScript dans le navigateur

Les datas WASM sont déclarée ici dans le fichier JS : 
![]({{site.url}}/static/upload_881e26d11784bbd5f477eb07da13a463.png)

Ici, 1024 est également un offset. Pour savoir ce qui sera exécuté par `fimport$0(1138)` il faut regarder la chaine de caractère à l'offset 164 (1138-164) dans les data.

```python
import base64

datas = "c3RoYWNreyVzfQAtKyAgIDBYMHgALTBYKzBYIDBYLTB4KzB4IDB4AG5hbgBpbmYATkFOAElORgAuAChudWxsKQBkaXNwbGF5X3Jlc3VsdCgnV2VsbCBkb25lICEhISBUaGUgZmxhZyBpcyA6ICVzJykAZGlzcGxheV9yZXN1bHQoJ0xlIGJydXRlIGZvcmNlIGVzdCBpbnRlcmRpdCAhISEnKQBkaXNwbGF5X3Jlc3VsdCgnUGFzc3dvcmQgaW5jb3JyZWN0ICEhIScpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABEACgAREREAAAAABQAAAAAAAAkAAAAACwAAAAAAAAAAEQAPChEREQMKBwABAAkLCwAACQYLAAALAAYRAAAAERERAAAAAAAAAAAAAAAAAAAAAAsAAAAAAAAAABEACgoREREACgAAAgAJCwAAAAkACwAACwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAMAAAAAAwAAAAACQwAAAAAAAwAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADgAAAAAAAAAAAAAADQAAAAQNAAAAAAkOAAAAAAAOAAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA8AAAAADwAAAAAJEAAAAAAAEAAAEAAAEgAAABISEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAAAAEhISAAAAAAAACQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAAAAAAAAAAACgAAAAAKAAAAAAkLAAAAAAALAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAwAAAAADAAAAAAJDAAAAAAADAAADAAAMDEyMzQ1Njc4OUFCQ0RFRg=="

print(base64.b64decode(datas)[1188-1024:].split(b"\x00")[0]) # Dans $1
print(base64.b64decode(datas)[1138-1024:].split(b"\x00")[0]) # Dans $33
```

Ce qui nous donne

```shell
b"display_result('Password incorrect !!!')"
b"display_result('Le brute force est interdit !!!')"
```

On sait donc maintenant que nous devons éviter la fonction $1 et que fimport$0(1188) nous indique un mot de passe incorrect.

L'appel à fimport$0(1138) est une fonctionnalité anti-bruteforce.

Il nous reste donc l'appel à la fonction $4 pour continuer. 

L'autre appel à fimport$0 se fait dans la fonction $2 ce qui semble être un bon point de sorti. Pour le confirmer, on peut modifier le WAT pour sauter dans cette fonction et voir ce qui se passe.

Pour repérer la fonction correspondante dans le fichier WAT, on peut chercher l'instruction `call 0`, qui apparait 3 fois

La fonction 5 affiche le message de mot de passe incorrect.

![]({{site.url}}/static/upload_f6ea1e5611e8ae5856d9de3929d041cd.png)

Ici, c'est la protection anti-bruteforce.

![]({{site.url}}/static/upload_55b9f843e78208e0ce2c8b53d3ebdf7f.png)

Cet appel, qui nous intéresse est dans la fonction 6
![]({{site.url}}/static/upload_30f0d51369f24de967b243a723c69e2c.png)

On va donc modifier la fonction exportée pour utiliser cette fonction et recompiler en WASM

![]({{site.url}}/static/upload_43271a208b131fe353c825c55dc98101.png)

On voit alors que le mot de passe testé est affiché en tant que flag.

![]({{site.url}}/static/upload_df6f9e595883e20911282fb1116bb985.png)

Notre but va donc être de trouver un chemin depuis la fonction $33 vers la fonction $2 

Notre unique sortie favorable de la fonction $33 était la fonction $4

![]({{site.url}}/static/upload_d3499d77e8f0f10e10ea7977f136ca7b.png)

Dans cette fonction, les fonctions de sortie possible sont $1 et $5. La fonction $1 étant la fonction indiquant un mauvais mot de passe, il faut donc accéder à $5

On voit une comparaison avec le nombre 27, on peut supposer qu'ici, il y a 26 caractères dans le mot de passe (26+\x00).


![]({{site.url}}/static/upload_254e7b80970543262e764f0eb7b56e83.png)

La fonction $5 fait un appel à $3 avec en paramètre le numéro 87.

![]({{site.url}}/static/upload_ae06a0d2c22c7358ce78bcc9d9cbabf8.png)

La fonction $3 se chargera de faire un XOR entre ses deux paramètres.

À ce stade, il est probable que chaque fonction calcul fasse un XOR d'un caractère du mot de passe et le compare à une valeur.

On remarque que $6 ressemble à $5 en changeant simplement le caractère passé au XOR et à la comparaison. 

![]({{site.url}}/static/upload_15882f6d809b716740eadb1a49dd745c.png)

On va donc extraire les paramètres passés à $3 en tant que clé XOR et les valeurs de comparaison.

```
XOR_KEY = [87,10,19,150,64,126,23,60,32,105,37,115,126,63,35,127,15,170,174,234,59,119,26,34,53,149,63]
XOR_PASS = [15,58,97,196,115,58,72,107,19,43,101,32,13,12,110,29,67,211,241,219,72,40,41,67,102,204]
```

À la fonction $31, on voit que le XOR est fait mais sans comparaison, il faut donc faire le XOR sur la valeur '**0**'

![]({{site.url}}/static/upload_9f2f7e9a0e83e823d43a851834b94072.png)

On peut alors calculer le mot de passe final :

```python
XOR_KEY = [87,10,19,150,64,126,23,60,32,105,37,115,126,63,35,127,15,170,174,234,59,119,26,34,53,149,63]
XOR_PASS = [15,58,97,196,115,58,72,107,19,43,101,32,13,12,110,29,67,211,241,219,72,40,41,67,102,204,0]

for x in range(len(XOR_KEY)):
    print(chr(XOR_KEY[x] ^ XOR_PASS[x]), end='')
```

![]({{site.url}}/static/upload_d42947e79cf23c70c1638cd9661d6737.png)
