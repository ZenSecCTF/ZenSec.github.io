# Baby CloudFlare

Le lien vers le challenge nous emène sur un site visiblement protégé
par un WAF qui nous empêche d'accéder au flag contenu à l'url:
`https://cloudflare.sthack.fr/flag`

A première vu le site web ne contient rien de spécial à l'exception du flag protégé.

Mais en regardant les headers renvoyé par le serveur ont peut voir qu'il existe un header plutôt étrange.
`X-Forwarded-from: dev-cloudflare.sthack.fr`

On s'empresse alors d'accéder à cette version de développement qui ne nous apprends pas grand chose de plus et l'accès au `/flag` n'est toujours pas possible.

Gardant en tête que le site est protégé par le WAF Cloudflare on peut supposer que celui-ci protége `*cloudflare.sthack.fr`

Un rapide host sur dev-cloudflare.sthack.fr nous donnera l'adresse ip du serveur.

Et si on utilise directement cette adresse `/flag` est bien accessible puisque l'on va bypasser le WAF qui le protège :+1: 
