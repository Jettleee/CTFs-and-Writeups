# Writeup: PwnSecCTF - "Snake" Challenge (Android)

This repository documents the methodology used to solve the Android **Snake** challenge from PwnSecCTF. This challenge stands out for making Frida unusable due to its protection mechanisms, forcing the attacker to combine static analysis, bytecode patching, and exploitation of a deserialization flaw.

## 🎯 Challenge Overview

* **Target application:** `Snake`
* **Protections encountered:**
* Strict root detection.
* Frida detection (making dynamic instrumentation unusable).


* **Main attack vector:** Deserialization vulnerability via the `SnakeYAML` library (CVE-2022-1471).

---

## 🛠️ Step 1: Bypassing Root Detection (Patching)

Since Frida is blocked by the application, the classic dynamic approach to bypass root detection isn't viable. We need to modify the application at the source.

**Methodology:**

1. **Decompilation:** Using tools like `Apktool` or `Apklab` to extract the application's Smali code.
2. **Analyzing the restriction:** Analyzing the code (initially visible via JADX) reveals a root detection function preventing the application from running on an emulator or rooted device.
3. **Manual patching:** Modifying the Smali code to invert or neutralize the root-check logic.
4. **Recompiling and signing:** The modified APK is recompiled, signed, then installed on the device. Once launched, the application works perfectly and requests external storage access permissions.

> <img width="768" height="692" alt="image" src="https://github.com/user-attachments/assets/e978bac3-4d23-4114-88c7-7809e64dc168" />

> <img width="551" height="651" alt="image" src="https://github.com/user-attachments/assets/fe7bbb78-637f-49c1-a4f4-58b71b13ce6d" />


---

## 🔍 Step 2: Static Analysis and Discovering the Mechanisms (Intents)

Once the application is functional, the goal is to understand its internal behavior and what it expects from the user.

**Methodology:**

1. **Inspecting Intents:** Code analysis reveals that the application listens for a specific `Intent`.
2. **Trigger conditions:** The application checks whether the received Intent contains an extra named `"SNAKE"` whose exact value must be `"BigBoss"`.
3. **Expected behavior:** If this condition is met, the application attempts to access external storage to read a YAML file located at `Snake/Skull_Face.yml`. If the file is found, its content is loaded and printed to the device logs.

> <img width="931" height="398" alt="image" src="https://github.com/user-attachments/assets/68d12f7c-9cdc-4615-aea8-70347c816c2f" />


---

## 🧠 Step 3: Reverse Engineering and Identifying the Vulnerability

Continuing to explore the source code, we find the pieces needed to forge our attack.

**Methodology:**

1. **Discovering the hidden class:** A class named `BigBoss` is identified. It is never called anywhere in the app's normal flow.
2. **Analyzing the `BigBoss` class:**
* This class loads a native library and calls a `stringFromJNI` function.
* It has a method that takes a string parameter. If that string is exactly `"Snaaaaaaaaaaaaaake"`, the flag is generated and printed to the logs.


3. **Identifying the flaw:** How do you call a class that's never instantiated? The answer lies in the YAML file. The application uses an outdated version of the `snakeyaml` library, vulnerable to a deserialization attack (CVE-2022-1471).

---

## 🧨 Step 4: Exploitation via YAML Deserialization

The final goal is to build a malicious YAML payload that forces the deserialization vulnerability to instantiate the hidden class with the correct parameter.

**Methodology:**

1. **Setting up the environment:** Creating a `Snake` folder at the root of the Android device's external storage, containing a file named `skull_Face.yml`.
2. **Forging the payload:** Inserting the following payload into the YAML file. This payload exploits the vulnerability to call the `BigBoss` class, passing it the expected string:
```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]

```



```
3. **Triggering the attack:** Using ADB (Android Debug Bridge) to send the forged Intent and trigger the reading of the malicious YAML file:
   ```bash
   adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss

```

4. **Retrieving the flag:** The deserialization executes, the class is successfully instantiated, and the flag is printed to logcat.

> <img width="773" height="25" alt="image" src="https://github.com/user-attachments/assets/52452cf5-128d-4c11-a295-51a49a5a0111" />


### 🎉 Final Result

The flag was successfully extracted from the logs:
**`PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}`**
