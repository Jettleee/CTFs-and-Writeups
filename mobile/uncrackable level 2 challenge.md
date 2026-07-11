
# 🕵️‍♂️ Lab Sécurité Android : Reverse Engineering Natif (UnCrackable Level 2)

Ce laboratoire documente l'analyse avancée d'une application Android qui dissimule sa logique critique dans une bibliothèque native (C/C++). Contrairement à une simple analyse de bytecode Java, ce challenge nécessite de faire le pont entre l'interface Java et le code binaire natif via JNI (Java Native Interface), en utilisant des outils comme **JADX** et **Ghidra**.

> **Environnement :** Laboratoire réalisé sous **Kali Linux**. Les recommandations du standard OWASP MASTG concernant l'analyse de bibliothèques ELF `.so` ont été appliquées.

---

## ☕ Phase 1 : Analyse Statique de la couche Java (JADX)

L'application présente un simple champ de texte et un bouton de validation. Pour comprendre ce qu'il se passe lors du clic, nous commençons par analyser le code Java.

### Étape 1 : Point d'entrée dans `MainActivity`
Nous ouvrons l'APK dans JADX pour inspecter la classe `MainActivity`, qui gère l'interface utilisateur.

```bash
jadx-gui UnCrackable-Level2.apk
```
*Observation : L'entrée utilisateur (la chaîne tapée) est récupérée puis envoyée à une méthode de validation externe, souvent sous la forme `m.a(userInput)`.*


<img width="1478" height="718" alt="image" src="https://github.com/user-attachments/assets/df799903-395f-46f5-ac45-69d3e89de022" />


### Étape 2 : Identification du pont JNI (`CodeCheck`)
En suivant le chemin de la donnée depuis `MainActivity`, nous aboutissons à la classe `CodeCheck`.

*Observation : Cette classe ne contient pas la logique de validation en clair. Elle révèle deux éléments cruciaux :*
1. Le chargement d'une librairie native : `System.loadLibrary("foo");`
2. La déclaration d'une méthode externe : `private native boolean bar(String s);`

<img width="761" height="438" alt="image" src="https://github.com/user-attachments/assets/155fa2dd-84dd-498b-9e60-8f352d333b07" />


---

## 🛠️ Phase 2 : Extraction et Analyse Binaire (Ghidra)

Le secret n'étant pas en Java, nous devons extraire et analyser la bibliothèque compilée `libfoo.so`.

### Étape 3 : Extraction de l'archive
L'APK contient différentes versions de la librairie selon l'architecture du processeur (ARM, x86). Une seule suffit pour notre analyse statique.

```bash
# Extraction de l'APK
unzip UnCrackable-Level2.apk -d uncrackable_l2

# Localisation des librairies natives
ls -R uncrackable_l2/lib
```
<img width="593" height="55" alt="image" src="https://github.com/user-attachments/assets/0e2e17c8-84d8-4b94-accf-bfa247d15ae7" />

<img width="1815" height="392" alt="image" src="https://github.com/user-attachments/assets/a052c188-e737-4d96-a759-5002520039a0" />


### Étape 4 : Importation dans Ghidra et recherche du symbole JNI
Nous lançons Ghidra (l'outil de reverse engineering de la NSA) pour analyser le fichier `uncrackable_l2/lib/x86/libfoo.so`.

*Action : Après l'analyse automatique, nous cherchons la fonction JNI exportée correspondant à la méthode `bar`.*
*Observation : Selon les conventions de nommage JNI, la fonction se nomme `Java_sg_vantagepoint_uncrackable2_CodeCheck_bar`.*
**![Capture 4 : Recherche du symbole JNI dans Ghidra](assets/capture_4_ghidra_jni.png)**

Étape 5 : Analyse du pseudo-code natif et découverte du secret

En ouvrant la fonction dans le décompilateur de Ghidra, nous inspectons le comportement du binaire.

Observation : Le pseudo-code (fenêtre de droite) révèle directement l'utilisation de la fonction builtin_strncpy.
C

builtin_strncpy(local_38, "Thanks for all the fish", 0x18);
// ... plus loin ...
iVar1 = strncmp(__s1, local_38, 0x17);

Contrairement à d'autres variantes de ce challenge où le secret est obfusqué (ex: stocké en hexadécimal inversé), cette version spécifique compile la chaîne secrète en clair. La fonction compare directement notre entrée (__s1) avec la variable local_38 contenant le secret non chiffré.

(Note : L'image correspondante est la capture d'écran globale de l'interface Ghidra montrant l'arbre des symboles à gauche et le pseudo-code à droite).
<img width="1909" height="722" alt="image" src="https://github.com/user-attachments/assets/0e827f59-44bb-400d-aef2-547ff5a5e9a1" />



## ✅ Phase 4 : Validation du Challenge

### Étape 8 : Test du secret
De retour sur l'émulateur, nous saisissons le secret découvert : `Thanks for all the fish`.
L'application valide l'entrée, confirmant le succès de notre reverse engineering.

<img width="514" height="969" alt="image" src="https://github.com/user-attachments/assets/7481abc8-89a8-45b4-a1c8-2d1f1abbe329" />


---

## 🧠 Résumé du flux logique de l'application (Data Flow)

Pour bien comprendre le pont entre les différentes technologies, voici le chemin suivi par la donnée saisie :

```text
Utilisateur saisit le texte
   ↓
[JAVA] MainActivity
   ↓
[JAVA] CodeCheck.a(input)
   ↓
[JNI]  CodeCheck.bar(input)
   ↓
[C/C++] libfoo.so
   ↓
[C/C++] strncmp(input, secret_interne)
   ↓
Retour du résultat (Succès / Échec)
```

**Conclusion :** Ce laboratoire démontre une technique d'obfuscation classique en sécurité mobile. Déplacer la logique sensible du code Java (facilement décompilable) vers du code natif C/C++ rend l'analyse plus ardue, nécessitant la maîtrise d'outils d'analyse binaire comme Ghidra et la compréhension de l'interface JNI.
```
