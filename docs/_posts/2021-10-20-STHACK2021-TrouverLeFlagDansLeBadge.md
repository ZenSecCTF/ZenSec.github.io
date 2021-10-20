---
title: Hardware - Trouver le flag dans le badge
category: Sthack2021
author: kZk
tags:
- sthack2021
- hardware
- rfid
- ctf
description: "Writeup Sthack 2021 - Trouver le flag dans le badge - Hardware"
---

*:cry: Malheureusement je n'ai pas pensé à prendre de screenshot pendant le CTF*

Le challenge débute avec l'acquisition d'un badge sans aucune information particulière.

Rapidement, on dégaine notre Proxmark 3 ( merci encore à @3ldidi pour le prêt du matos :wink:) et on s'attaque à ce petit badge.

Côté software on va s'appuyer sur le fork de pm3 par RRG / Iceman repo disponible [ici](https://github.com/RfidResearchGroup/proxmark3)

La première étape consiste à déterminer si notre badge fonctionne en haute ou en basse fréquence, généralement les badges RFID fonctionnent en haute fréquence on va partir sur cette hypothèse.

Rapidement on réalise une discovery à l'aide de la commande suivante:

```sh
$ hf search
```

On apprend que notre badge utilise la technologie *iClass*, on a donc accès à toute une suite de commandes pour ce type de badge.


```sh
$ hf iclass help
```

Notre objectif sera bien évidemment de dump le contenu du badge, mais avant ça il va falloir trouver la clé de déchiffrement, la première piste consistera à checker les clés par défaut.

On peut trouver un dico adapté directement dans notre répo proxmark3

```sh
 ✘ kzk@kZk  ~/Documents/proxmark3   master  ls -lah client/dictionaries 
total 92K
drwxr-xr-x  3 kzk kzk 4,0K 16 oct.  02:59 .
drwxr-xr-x 15 kzk kzk 4,0K 16 oct.  03:08 ..
drwxr-xr-x  2 kzk kzk 4,0K 16 oct.  02:59 extras
-rw-r--r--  1 kzk kzk  630 16 oct.  02:59 iclass_default_keys.dic
-rw-r--r--  1 kzk kzk  21K 16 oct.  02:59 mfc_default_keys.dic
-rw-r--r--  1 kzk kzk  13K 16 oct.  02:59 mfc_keys_bmp_sorted.dic
-rw-r--r--  1 kzk kzk  13K 16 oct.  02:59 mfc_keys_icbmp_sorted.dic
-rw-r--r--  1 kzk kzk  741 16 oct.  02:59 mfc_keys_mrzd_sorted.dic
-rw-r--r--  1 kzk kzk 2,0K 16 oct.  02:59 mfdes_default_keys.dic
-rw-r--r--  1 kzk kzk 1,1K 16 oct.  02:59 mfp_default_keys.dic
-rw-r--r--  1 kzk kzk  185 16 oct.  02:59 mfulc_default_keys.dic
-rw-r--r--  1 kzk kzk 2,2K 16 oct.  02:59 t55xx_default_pwds.dic
```

On tente notre chance avec le dico `iclass_default_keys.dic` avec la commande suivante

```sh
$ hf iclass chk f iclass_default_keys.dic
```

Bingo, :wink: il nous reste plus qu'à dumper le contenu du badge (vous avez bien compris que n'ayant plus le badge je me souviens plus de la clé qui match :disappointed: )

```sh
$ hf iclass dump k {key} 
```

Allons voir ce qu'il y a la dedans !

```sh
 kzk@kZk  ~/Documents/proxmark3   master  hexdump -C hf-iclass-45005B02F9FF12E0-dump.bin
00000000  45 00 5b 02 f9 ff 12 e0  12 ff ff ff 7f 1f ff 3c  |E.[............<|
00000010  fe ff ff ff ff ff ff ff  9d df d6 aa 10 fb f9 98  |................|
00000020  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00000030  03 03 03 03 00 03 e0 17  22 bd 45 04 30 c2 0e 91  |........".E.0...|
00000040  2a d4 c8 21 1f 99 68 71  2a d4 c8 21 1f 99 68 71  |*..!..hq*..!..hq|
00000050  73 74 68 61 63 6b 7b 6c  5f 31 63 6c 34 35 35 5f  |sthack{l_1cl455_|
00000060  34 5f 44 34 6c 6c 34 35  7d 00 00 00 00 00 00 00  |4_D4ll45}.......|
00000070  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
```

Et voilà ! Un bon petit chall sympa qui permet de se familiariser avec le Proxmark !
