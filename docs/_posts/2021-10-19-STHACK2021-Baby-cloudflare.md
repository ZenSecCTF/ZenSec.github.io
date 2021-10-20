---
title: MISC - Baby CloudFlare
category: Sthack2021
author: kZk
tags:
- sthack2021
- misc
- ctf
description: "Writeup Sthack 2021 - Baby CloudFlare - MISC"
---
Le lien vers le challenge nous emmène sur un site visiblement protégé
par un WAF qui nous empêche d'accéder au flag contenu à l'URL:

```html
https://cloudflare.sthack.fr/flag
```

À première vu le site web ne contient rien de spécial à l'exception du flag protégé.

Mais en regardant les headers renvoyé par le serveur on peut voir qu'il existe un header plutôt étrange.

```html
X-Forwarded-from: dev-cloudflare.sthack.fr
```

On s'empresse alors d'accéder à cette version de développement qui ne nous apprends pas grand-chose de plus et l'accès au `/flag` n'est toujours pas possible.

Gardant en tête que le site est protégé par le WAF Cloudflare on peut supposer que celui-ci protège 

```html
*cloudflare.sthack.fr
`````

Un rapide `host` sur dev-cloudflare.sthack.fr nous donnera l'adresse IP du serveur.

```shell
$ host dev-cloudflare.sthack.fr
dev-cloudflare.sthack.fr has address 79.125.69.136
```

Et si on utilise directement cette adresse `/flag` est bien accessible puisque l'on va contourner le WAF qui le protège :+1: 
