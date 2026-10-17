
# 🕵️‍♂️ Android Security Lab: Native Reverse Engineering (UnCrackable Level 2)

This lab documents the advanced analysis of an Android application that hides its critical logic inside a native library (C/C++). Unlike a simple Java bytecode analysis, this challenge requires bridging the Java interface and the native binary code via JNI (Java Native Interface), using tools like **JADX** and **Ghidra**.

> **Environment:** Lab performed on **Kali Linux**. The OWASP MASTG standard's recommendations for analyzing ELF `.so` libraries were applied.

---

## ☕ Phase 1: Static Analysis of the Java Layer (JADX)

The application presents a simple text field and a validate button. To understand what happens on click, we start by analyzing the Java code.

### Step 1: Entry point in `MainActivity`
We open the APK in JADX to inspect the `MainActivity` class, which handles the user interface.

```bash
jadx-gui UnCrackable-Level2.apk
```
*Observation: The user input (the typed string) is retrieved and then sent to an external validation method, usually in the form `m.a(userInput)`.*


<img width="1478" height="718" alt="image" src="https://github.com/user-attachments/assets/df799903-395f-46f5-ac45-69d3e89de022" />


### Step 2: Identifying the JNI bridge (`CodeCheck`)
Following the data path from `MainActivity`, we end up at the `CodeCheck` class.

*Observation: This class does not contain the validation logic in plain sight. It reveals two crucial elements:*
1. Loading a native library: `System.loadLibrary("foo");`
2. Declaring an external method: `private native boolean bar(String s);`

<img width="761" height="438" alt="image" src="https://github.com/user-attachments/assets/155fa2dd-84dd-498b-9e60-8f352d333b07" />


---

## 🛠️ Phase 2: Binary Extraction and Analysis (Ghidra)

Since the secret isn't in Java, we need to extract and analyze the compiled `libfoo.so` library.

### Step 3: Extracting the archive
The APK contains different versions of the library depending on the CPU architecture (ARM, x86). Only one is needed for our static analysis.

```bash
# Extracting the APK
unzip UnCrackable-Level2.apk -d uncrackable_l2

# Locating the native libraries
ls -R uncrackable_l2/lib
```
<img width="593" height="55" alt="image" src="https://github.com/user-attachments/assets/0e2e17c8-84d8-4b94-accf-bfa247d15ae7" />

<img width="1815" height="392" alt="image" src="https://github.com/user-attachments/assets/a052c188-e737-4d96-a759-5002520039a0" />


### Step 4: Importing into Ghidra and finding the JNI symbol
We launch Ghidra (the NSA's reverse engineering tool) to analyze the `uncrackable_l2/lib/x86/libfoo.so` file.

*Action: After the automatic analysis, we look for the exported JNI function matching the `bar` method.*
*Observation: Following JNI naming conventions, the function is named `Java_sg_vantagepoint_uncrackable2_CodeCheck_bar`.*
**![Capture 4: Finding the JNI symbol in Ghidra](assets/capture_4_ghidra_jni.png)**

Step 5: Analyzing the native pseudo-code and discovering the secret

Opening the function in Ghidra's decompiler, we inspect the binary's behavior.

Observation: The pseudo-code (right-hand window) directly reveals the use of the `__builtin_strncpy` function.
C

```
__builtin_strncpy(local_38, "Thanks for all the fish", 0x18);
// ... further down ...
iVar1 = strncmp(__s1, local_38, 0x17);
```

Unlike other variants of this challenge where the secret is obfuscated (e.g. stored as reversed hex), this specific version compiles the secret string in plain sight. The function directly compares our input (`__s1`) with the `local_38` variable holding the unencrypted secret.

(Note: The corresponding image is the overall screenshot of the Ghidra interface, showing the symbol tree on the left and the pseudo-code on the right).
<img width="1909" height="722" alt="image" src="https://github.com/user-attachments/assets/0e827f59-44bb-400d-aef2-547ff5a5e9a1" />



## ✅ Phase 4: Challenge Validation

### Step 8: Testing the secret
Back on the emulator, we enter the discovered secret: `Thanks for all the fish`.
The application accepts the input, confirming our reverse engineering was successful.

<img width="514" height="969" alt="image" src="https://github.com/user-attachments/assets/7481abc8-89a8-45b4-a1c8-2d1f1abbe329" />


---

## 🧠 Summary of the Application's Logic Flow (Data Flow)

To clearly understand the bridge between the different technologies, here's the path followed by the input data:

```text
User enters text
   ↓
[JAVA] MainActivity
   ↓
[JAVA] CodeCheck.a(input)
   ↓
[JNI]  CodeCheck.bar(input)
   ↓
[C/C++] libfoo.so
   ↓
[C/C++] strncmp(input, internal_secret)
   ↓
Result returned (Success / Failure)
```

**Conclusion:** This lab demonstrates a classic obfuscation technique in mobile security. Moving sensitive logic from Java code (easily decompiled) into native C/C++ code makes analysis harder, requiring proficiency with binary analysis tools like Ghidra and an understanding of the JNI interface.
```
