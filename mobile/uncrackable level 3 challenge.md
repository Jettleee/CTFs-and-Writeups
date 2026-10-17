# Writeup: OWASP UnCrackable Level 3 (Android)

This repository contains the detailed methodology and resolution steps for OWASP's **UnCrackable Level 3** challenge. This challenge implements advanced protections such as root detection, dynamic Frida detection at the native level (`.so`), and a cryptographic check implemented in C.

## 🎯 Challenge Overview

* **Goal:** Find the secret (flag) hidden in the application.
* **Protections encountered:**
* Root detection (Java layer)
* Anti-tampering / anti-Frida detection (Native layer)
* XOR encryption for flag validation



---

## 🛠️ Step 1: Initial Analysis and Root Detection

On the first launch on an emulator or rooted device, the application closes immediately after displaying an error message.

**Methodology:**

1. **Static Analysis:** By decompiling the APK (with `JADX` or `Apktool`), we identify the `RootDetection` class.
2. This class uses three distinct methods (`checkRoot1`, `checkRoot2`, `checkRoot3`) to check for the presence of the `su` binary, `test-keys`, and other root-related files.
3. **Resolution:** The approach is to write a small Frida script to hook these three Java methods and force them to return `false`, simulating a non-rooted environment.

> <img width="433" height="622" alt="image" src="https://github.com/user-attachments/assets/7ff05ea1-0e5a-4094-84a5-0267c38979b5" />

> <img width="1111" height="656" alt="image" src="https://github.com/user-attachments/assets/bf65cf3b-61a1-4a6c-ac8a-12e4fc6de933" />


---

## 🛡️ Step 2: Detecting and Bypassing Frida (Native Layer)

After running the first Frida script, the application crashes unexpectedly, cutting off the Frida connection.

**Methodology:**

1. **Dynamic Analysis (Logs):** Inspecting Android's `logcat` at the moment of the crash, we notice a call to a `goodbye` function coming from the native library **`libfoo.so`**.
2. **Reverse engineering the lib (`Ghidra`):**
* Analyzing `libfoo.so` reveals that an init function (`_INIT_0`) spawns a secondary thread right at startup.
* This thread repeatedly reads the `/proc/self/maps` file (which lists the process's memory regions).
* It uses the C function `strstr` to search for the string `"frida"`. If found, the program calls `goodbye` and stops.


3. **Resolution:** We need to update our Frida script to hook the native `strstr` function. If the passed argument contains the word "frida", we force `strstr`'s return value to `0` (indicating no match was found).

> <img width="755" height="440" alt="image" src="https://github.com/user-attachments/assets/61ad5eef-92b7-47d7-8931-81334c66f686" />

<img width="1101" height="339" alt="image" src="https://github.com/user-attachments/assets/26b81ee0-df9f-4fa3-a4f2-8c136a933c55" />

<img width="1095" height="330" alt="image" src="https://github.com/user-attachments/assets/6f6f1b7a-5a64-402a-aab2-612f01e12c39" />




---

## 🔑 Step 3: Cryptographic Analysis and Flag Extraction

Once the application is stabilized (root and Frida bypassed), we can analyze the password validation logic.

**Methodology:**

1. **Tracing the input:** The user input is sent to the native `bar` method in `libfoo.so`.
2. **Identifying the constraints:**
* A length check requires our string to be exactly **24 characters**.
* The application generates a global key (`xorkey`) in the Java layer and sends it to native initialization.


3. **Analyzing the validation function (`FUN_001012c0`):**
* The function loads a series of hardcoded hex bytes into memory.
* It runs a loop applying a **XOR** operation between our input, the hex bytes, and the `xorkey`.


4. **Extraction (CyberChef):** Rather than brute-forcing the validation, we can reverse the algorithm. We just need to extract the hex sequence from Ghidra, then recreate the operation offline using the `xorkey`.

> <img width="877" height="233" alt="image" src="https://github.com/user-attachments/assets/f4a3dad3-9e4a-4358-84cc-f508fcdb2f9e" />

> <img width="543" height="465" alt="image" src="https://github.com/user-attachments/assets/d3b9fd0d-8d77-4114-b1da-ab8093d64850" />

> <img width="621" height="366" alt="image" src="https://github.com/user-attachments/assets/83e7e023-3d59-4201-a404-54209a9bacad" />


### Final result

The flag obtained after decryption is: **`making owasp great again`**
