# 🧨 Mobile Challenge: FireStorm - Writeup
**Author:** Youssef CHARAF  
**Domain:** Mobile Security / Reverse Engineering & Hooking  
**Main tool:** Frida & Python  

---

## 📝 1. Static Analysis
The first step was decompiling the APK binary using **JADX**.

* **Observation:** While exploring the `com.pwnsec.firestorm` package, we identified a `MainActivity` class.
* **Finding:** A method named `Password()` is present. This method dynamically generates a password, but it is **never called** in the app's normal flow.
* **Goal:** Use dynamic instrumentation to force this method to execute in memory.

<img width="1216" height="643" alt="image" src="https://github.com/user-attachments/assets/a6e809c4-61c8-4e44-87b9-b344c8f74482" />


---

## ⚙️ 2. Environment Setup
For this lab, we went with a **Windows Host -> Android Emulator** setup to maximize Frida's stability.

* **Target:** Pixel 3 Emulator (Android 11 - Google APIs), `x86_64` architecture.
* **Privileges:** Root access enabled via `adb root`.
* **Server:** Deployment of `frida-server-17.9.1-android-x86_64`.

```powershell
# Deploying the server
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

<img width="1113" height="190" alt="image" src="https://github.com/user-attachments/assets/652962f1-a607-450f-a765-57e7944ffd06" />



<img width="1104" height="157" alt="image" src="https://github.com/user-attachments/assets/926af187-a80a-4dd9-90e6-ed31285c8178" />

---

## 🚀 3. Dynamic Analysis (Runtime Hooking)
Exploitation was carried out using a JavaScript script injected via Frida.

### Hooking Strategy
We used `Java.choose` to locate the active `MainActivity` instance in the app's live memory. To avoid race conditions, a 5-second delay was added.

**Script: `frida-hook.js`**
```javascript
Java.perform(function() {
    setTimeout(function() {
        Java.choose('com.pwnsec.firestorm.MainActivity', {
            onMatch: function(instance) {
                var pass = instance.Password();
                console.log("[🔥] FIREBASE PASSWORD: " + pass);
            },
            onComplete: function() {}
        });
    }, 5000);
});
```

### Running the Attack
To bypass the "spawn" restrictions, we attached directly to the **PID** of the running process.

<img width="1007" height="362" alt="image" src="https://github.com/user-attachments/assets/d3dd0723-e144-40ec-a434-aa5db43c73ad" />

---

## 🏁 4. Flag Exfiltration (Firebase)
The final step was using the recovered credentials to query the Firebase real-time database.

* **Credentials:** Email (extracted via static analysis) + Password (extracted via Frida).
* **Tool:** Python script using the `pyrebase4` library.

<img width="983" height="120" alt="image" src="https://github.com/user-attachments/assets/ff74d3ec-1b5d-4400-a49d-ce454ee4ceff" />



**Exfiltration result:**
The script authenticated successfully and retrieved the secured flag from the database node.



---

## 🧠 Conclusion
This challenge shows that security through obscurity (hiding a function) is ineffective against dynamic instrumentation. Even an unused function can be invoked by an attacker with root privileges on the device to extract runtime secrets.

---

### 📂 Project Structure
```text
.
├── FireStorm.apk          # Target application
├── frida-hook.js          # JavaScript injection script
├── get-flag.py            # Python exfiltration script
└── README.md              # Lab documentation
```

