# 🧨 Challenge Mobile : FireStorm - Writeup
**Auteur :** Youssef CHARAF  
**Domaine :** Sécurité Mobile / Reverse Engineering & Hooking  
**Outil principal :** Frida & Python  

---

## 📝 1. Analyse Statique (Static Analysis)
La première étape a consisté à décompiler le binaire APK à l'aide de **JADX**.

* **Observation :** En explorant le package `com.pwnsec.firestorm`, nous avons identifié une classe `MainActivity`.
* **Découverte :** Une méthode nommée `Password()` est présente. Cette méthode génère un mot de passe de manière dynamique, mais elle n'est **jamais appelée** dans le flux normal de l'application.
* **Objectif :** Utiliser l'instrumentation dynamique pour forcer l'exécution de cette méthode en mémoire.

<img width="1216" height="643" alt="image" src="https://github.com/user-attachments/assets/a6e809c4-61c8-4e44-87b9-b344c8f74482" />


---

## ⚙️ 2. Configuration de l'environnement
Pour ce laboratoire, nous avons opté pour une architecture **Hôte Windows -> Émulateur Android** afin de maximiser la stabilité de Frida.

* **Cible :** Émulateur Pixel 3 (Android 11 - Google APIs), Architecture `x86_64`.
* **Privilèges :** Accès Root activé via `adb root`.
* **Serveur :** Déploiement de `frida-server-17.9.1-android-x86_64`.

```powershell
# Déploiement du serveur
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

<img width="1113" height="190" alt="image" src="https://github.com/user-attachments/assets/652962f1-a607-450f-a765-57e7944ffd06" />



<img width="1104" height="157" alt="image" src="https://github.com/user-attachments/assets/926af187-a80a-4dd9-90e6-ed31285c8178" />

---

## 🚀 3. Analyse Dynamique (Runtime Hooking)
L'exploitation a été réalisée à l'aide d'un script JavaScript injecté par Frida. 

### Stratégie de Hooking
Nous avons utilisé `Java.choose` pour localiser l'instance active de `MainActivity` dans la mémoire vive de l'application. Pour éviter les erreurs de synchronisation, un délai de 5 secondes a été ajouté.

**Script : `frida-hook.js`**
```javascript
Java.perform(function() {
    setTimeout(function() {
        Java.choose('com.pwnsec.firestorm.MainActivity', {
            onMatch: function(instance) {
                var pass = instance.Password();
                console.log("[🔥] MOT DE PASSE FIREBASE : " + pass);
            },
            onComplete: function() {}
        });
    }, 5000);
});
```

### Exécution de l'attaque
Pour contourner les restrictions de "spawn", nous nous sommes attachés directement au **PID** du processus actif.

<img width="1007" height="362" alt="image" src="https://github.com/user-attachments/assets/d3dd0723-e144-40ec-a434-aa5db43c73ad" />

---

## 🏁 4. Exfiltration du Flag (Firebase)
La dernière étape a consisté à utiliser les identifiants récupérés pour interroger la base de données Firebase en temps réel.

* **Identifiants :** Email (extrait par analyse statique) + Password (extrait par Frida).
* **Outil :** Script Python utilisant la bibliothèque `pyrebase4`.

<img width="983" height="120" alt="image" src="https://github.com/user-attachments/assets/ff74d3ec-1b5d-4400-a49d-ce454ee4ceff" />



**Résultat de l'exfiltration :**
Le script s'est authentifié avec succès et a récupéré le flag sécurisé dans le nœud de la base de données.



---

## 🧠 Conclusion
Ce challenge démontre que la sécurité par l'obscurité (cacher une fonction) est inefficace contre l'instrumentation dynamique. Même une fonction inutilisée peut être invoquée par un attaquant possédant les privilèges root sur l'appareil pour extraire des secrets de runtime.

---

### 📂 Arborescence du projet
```text
.
├── FireStorm.apk          # Application cible
├── frida-hook.js          # Script d'injection JavaScript
├── get-flag.py            # Script d'exfiltration Python
└── README.md              # Documentation du lab
```


