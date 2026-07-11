# Writeup : PwnSecCTF - Challenge "Snake" (Android)

Ce dépôt documente la méthodologie de résolution du challenge Android **Snake** issu du PwnSecCTF. Ce défi se distingue par l'impossibilité d'utiliser Frida en raison de ses mécanismes de protection, obligeant l'attaquant à combiner l'analyse statique, le patching de bytecode et l'exploitation d'une faille de désérialisation.

## 🎯 Aperçu du Challenge

* **Application cible :** `Snake`
* **Protections rencontrées :**
* Détection de Root stricte.
* Détection de Frida (rendant l'instrumentation dynamique inutilisable).


* **Vecteur d'attaque principal :** Faille de désérialisation via la bibliothèque `SnakeYAML` (CVE-2022-1471).

---

## 🛠️ Étape 1 : Contournement de la Détection de Root (Patching)

Puisque Frida est bloqué par l'application, l'approche dynamique classique pour contourner la détection de root n'est pas viable. Il faut modifier l'application à la source.

**Méthodologie :**

1. **Décompilation :** Utilisation d'outils comme `Apktool` ou `Apklab` pour extraire le code Smali de l'application.
2. **Analyse de la restriction :** L'analyse du code (visible initialement via JADX) révèle une fonction de détection de root empêchant l'application de s'exécuter sur un émulateur ou un appareil rooté.
3. **Patching manuel :** Modification du code Smali pour inverser ou neutraliser la logique de vérification du root.
4. **Recompilation et Signature :** L'APK modifié est recompilé, signé, puis installé sur l'appareil. Une fois lancée, l'application fonctionne parfaitement et demande les permissions d'accès au stockage externe.

> <img width="768" height="692" alt="image" src="https://github.com/user-attachments/assets/e978bac3-4d23-4114-88c7-7809e64dc168" />

> <img width="551" height="651" alt="image" src="https://github.com/user-attachments/assets/fe7bbb78-637f-49c1-a4f4-58b71b13ce6d" />


---

## 🔍 Étape 2 : Analyse Statique et Découverte des Mécanismes (Intents)

Une fois l'application fonctionnelle, l'objectif est de comprendre son fonctionnement interne et ce qu'elle attend de l'utilisateur.

**Méthodologie :**

1. **Inspection des Intents :** L'analyse du code révèle que l'application écoute un `Intent` spécifique.
2. **Conditions de déclenchement :** L'application vérifie si l'Intent reçu contient une donnée supplémentaire (Extra) nommée `"SNAKE"` dont la valeur exacte doit être `"BigBoss"`.
3. **Comportement attendu :** Si cette condition est remplie, l'application tente d'accéder au stockage externe pour lire un fichier YAML situé dans `Snake/Skull_Face.yml`. Si le fichier est trouvé, son contenu est chargé et affiché dans les logs de l'appareil.

> <img width="931" height="398" alt="image" src="https://github.com/user-attachments/assets/68d12f7c-9cdc-4615-aea8-70347c816c2f" />


---

## 🧠 Étape 3 : Rétro-ingénierie et Identification de la Vulnérabilité

En continuant d'explorer le code source, nous découvrons les éléments nécessaires pour forger notre attaque.

**Méthodologie :**

1. **Découverte de la classe cachée :** Une classe nommée `BigBoss` est identifiée. Elle n'est appelée nulle part dans le flux normal de l'application.
2. **Analyse de la classe `BigBoss` :**
* Cette classe charge une bibliothèque native et appelle une fonction `stringFromJNI`.
* Elle possède une méthode qui prend une chaîne de caractères en paramètre. Si cette chaîne est exactement `"Snaaaaaaaaaaaaaake"`, le flag est généré et affiché dans les logs.


3. **Identification de la faille :** Comment appeler une classe qui n'est jamais instanciée ? La réponse réside dans le fichier YAML. L'application utilise une ancienne version de la bibliothèque `snakeyaml`, vulnérable à une attaque de désérialisation (CVE-2022-1471).

---

## 🧨 Étape 4 : Exploitation via Désérialisation YAML

L'objectif final est de construire un payload YAML malveillant qui va forcer la vulnérabilité de désérialisation à instancier la classe cachée avec le bon paramètre.

**Méthodologie :**

1. **Création de l'environnement :** Création d'un dossier `Snake` à la racine du stockage externe de l'appareil Android, contenant un fichier nommé `skull_Face.yml`.
2. **Forgeage du Payload :** Insertion de la charge utile suivante dans le fichier YAML. Ce payload exploite la vulnérabilité pour appeler la classe `BigBoss` en lui passant la chaîne attendue :
```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]

```



```
3. **Déclenchement de l'attaque :** Utilisation d'ADB (Android Debug Bridge) pour envoyer l'Intent forgé et déclencher la lecture du fichier YAML malveillant :
   ```bash
   adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss

```

4. **Récupération du Flag :** La désérialisation s'exécute, la classe est instanciée avec succès, et le flag est imprimé dans le logcat.

> <img width="773" height="25" alt="image" src="https://github.com/user-attachments/assets/52452cf5-128d-4c11-a295-51a49a5a0111" />


### 🎉 Résultat Final

Le flag a été extrait avec succès depuis les logs :
**`PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}`**
