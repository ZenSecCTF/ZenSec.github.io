---
title: Forensic - Docker Image
category: Sthack2021
author: karzemrok
tags:
- sthack2021
- forensic
- ctf
description: "Writeup Sthack 2021 - Docker Image - Forensic"
---
# Forensic Docker

## Description


I lost the password i use to encrypt my flag file. Could you retreive my flag ?
`sudo docker pull mayfly277/sthack2021_docker_forensic`

## Résolution

La première étape est de connaitre les différentes commandes docker utilisée lors de la construction de l'image.

Pour cela on peut le faire à la main ou en utilisant l'outil [dive](https://github.com/wagoodman/dive).

```sh
$ docker pull mayfly277/sthack2021_docker_forensic
$ docker save sthack2021_docker_forensic.tar
```

On peut lister les fichiers JSON:

```sh
$ tar -tvf sthack2021_docker_forensic.tar '*.json'     
-rw-r--r-- 0/0            2437 2021-09-09 15:40 df9bf87b22e3a6cb1e50a016f9add403c2024cd8dc82204f40979aa47ed58ed1.json
-rw-r--r-- 0/0             617 1970-01-01 01:00 manifest.json
$ tar xfO sthack2021_docker_forensic.tar 'df9bf87b22e3a6cb1e50a016f9add403c2024cd8dc82204f40979aa47ed58ed1.json' | jq '.history[] | .created_by' -r
/bin/sh -c #(nop) ADD file:d2abf27fe2e8b0b5f4da68c018560c73e11c53098329246e3e6fe176698ef941 in / 
/bin/sh -c #(nop)  CMD ["bash"]
/bin/sh -c apt update -y
/bin/sh -c apt install -y curl openssl
/bin/sh -c #(nop) COPY file:1a7183ad2543f172d82f35bd319cae411595c5fdfb76b1da1da6b6768ac3df6e in / 
/bin/sh -c echo -n $(curl -s https://pastebin.com/raw/ErwwdMja) | openssl enc -aes-256-cbc -iter 10 -pass pass:$(cat /pass.txt) -out flag.enc
/bin/sh -c rm /pass.txt
```

On voit dans les commandes la suppression du fichier `pass.txt` qui a servi dans la commande précédente au chiffrement d'un Pastebin via une commande OpenSSL.

On suppose donc qu'il a été ajouté grâce au `COPY` de l'étape d'avant.

Pour être sûr, il est possible de chercher le fichier `pass.txt` dans toutes les couches de l'image :

```sh
$ mkdir docker_image
$ tar xvf sthack2021_docker_forensic.tar -C docker_image
$ find docker_image -name layer.tar -exec tar xfO {} 'pass.txt' 2>/dev/null \;
MySupAAAS3cure_PassSSS
```

Le mot de passe est donc `MySupAAAS3cure_PassSSS`. Nous devons maintenant récupérer le fichier chiffré par OpenSSL.

```sh
$ find docker_image -name layer.tar -exec tar xfO {} 'flag.enc' 2>/dev/null \; > flag.enc
```

Il ne nous reste plus qu'à exécuter la commande OpenSSL de déchiffrement.

```sh 
$ openssl aes-256-cbc -d -iter 10 -in flag.enc              
enter aes-256-cbc decryption password:
STHACK{08ae895ddfdcbdb5c8cfb848e7c7ae23}
```
