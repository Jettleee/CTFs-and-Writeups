# Writeup : OWASP UnCrackable Level 3 (Android)

Ce dépôt contient la méthodologie détaillée et les étapes de résolution du challenge **UnCrackable Level 3** de l'OWASP. Ce défi met en œuvre des protections avancées telles que la détection de root, la détection dynamique de Frida au niveau natif (`.so`), et une vérification cryptographique implémentée en C.

## 🎯 Aperçu du Challenge

* **Objectif :** Trouver le secret (flag) caché dans l'application.
* **Protections rencontrées :**
* Détection de Root (Couche Java)
* Détection anti-tampering / anti-Frida (Couche Native)
* Chiffrement XOR pour la validation du flag



---

## 🛠️ Étape 1 : Analyse Initiale et Détection de Root

Lors du premier lancement de l'application sur un émulateur ou un appareil rooté, l'application se ferme immédiatement après avoir affiché un message d'erreur.

**Méthodologie :**

1. **Analyse Statique :** En décompilant l'APK (avec `JADX` ou `Apktool`), nous identifions la classe `RootDetection`.
2. Cette classe utilise trois méthodes distinctes (`checkRoot1`, `checkRoot2`, `checkRoot3`) pour vérifier la présence du binaire `su`, des clés de test (`test-keys`) et d'autres fichiers liés au root.
3. **Résolution :** L'approche consiste à écrire un petit script Frida pour intercepter ("hooker") ces trois méthodes Java et les forcer à retourner `false`, simulant ainsi un environnement non-rooté.

> <img width="433" height="622" alt="image" src="https://github.com/user-attachments/assets/7ff05ea1-0e5a-4094-84a5-0267c38979b5" />

> <img width="1111" height="656" alt="image" src="https://github.com/user-attachments/assets/bf65cf3b-61a1-4a6c-ac8a-12e4fc6de933" />


---

## 🛡️ Étape 2 : Détection et Contournement de Frida (Couche Native)

Après avoir exécuté le premier script Frida, l'application crashe de manière inattendue, coupant la connexion avec Frida.

**Méthodologie :**

1. **Analyse Dynamique (Logs) :** En inspectant le `logcat` d'Android au moment du crash, nous remarquons un appel à une fonction `goodbye` provenant de la bibliothèque native **`libfoo.so`**.
2. **Rétro-ingénierie de la lib (`Ghidra`) :** * L'analyse de `libfoo.so` révèle qu'une fonction d'initialisation (`_INIT_0`) lance un thread secondaire dès le démarrage.
* Ce thread lit en boucle le fichier `/proc/self/maps` (qui liste les zones mémoire du processus).
* Il utilise la fonction C `strstr` pour chercher la chaîne de caractères `"frida"`. Si elle est trouvée, le programme appelle `goodbye` et s'arrête.


3. **Résolution :** Il faut mettre à jour notre script Frida pour intercepter la fonction native `strstr`. Si l'argument passé contient le mot "frida", on force la valeur de retour de `strstr` à `0` (indiquant qu'aucune correspondance n'a été trouvée).

> <img width="755" height="440" alt="image" src="https://github.com/user-attachments/assets/61ad5eef-92b7-47d7-8931-81334c66f686" />

<img width="1101" height="339" alt="image" src="https://github.com/user-attachments/assets/26b81ee0-df9f-4fa3-a4f2-8c136a933c55" />

<img width="1095" height="330" alt="image" src="https://github.com/user-attachments/assets/6f6f1b7a-5a64-402a-aab2-612f01e12c39" />




---

## 🔑 Étape 3 : Analyse Cryptographique et Extraction du Flag

Une fois l'application stabilisée (Root et Frida bypassés), nous pouvons analyser la logique de validation du mot de passe.

**Méthodologie :**

1. **Traçage de l'input :** L'entrée utilisateur est envoyée à la méthode native `bar` dans `libfoo.so`.
2. **Identification des contraintes :**
* Une vérification de la longueur exige que notre chaîne fasse exactement **24 caractères**.
* L'application génère une clé globale (`xorkey`) dans la couche Java et l'envoie à l'initialisation native.


3. **Analyse de la fonction de validation (`FUN_001012c0`) :**
* La fonction charge en mémoire une série d'octets hexadécimaux figés en dur.
* Elle effectue une boucle appliquant une opération **XOR** entre notre input, les octets hexadécimaux et la clé `xorkey`.


4. **Extraction (CyberChef) :** Plutôt que de forcer la validation, nous pouvons inverser l'algorithme. Il suffit d'extraire la séquence hexadécimale depuis Ghidra, puis de recréer l'opération hors-ligne avec la clé `xorkey`.

> <img width="877" height="233" alt="image" src="https://github.com/user-attachments/assets/f4a3dad3-9e4a-4358-84cc-f508fcdb2f9e" />

> <img width="543" height="465" alt="image" src="https://github.com/user-attachments/assets/d3b9fd0d-8d77-4114-b1da-ab8093d64850" />

> <img width="621" height="366" alt="image" src="https://github.com/user-attachments/assets/83e7e023-3d59-4201-a404-54209a9bacad" />


### Résultat final

Le flag obtenu après déchiffrement est : **`making owasp great again`**
