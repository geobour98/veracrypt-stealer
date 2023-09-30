# VeraCrypt Stealer

This is the assignment part of the course: Malware Development Intermediate, by sektor7. The course can be found here: [MalDev Intermediate](https://institute.sektor7.net/rto-maldev-intermediate). The purpose of this assignment is to steal the password (without using a keylogger), which a user types to mount an encrypted disk (volume), created with VeraCrypt software. To achieve it, the assignment consists of 3 parts:
1. **VCsniff**: Use **IAT Hooking** to capture the password from the API `WideCharToMultiByte`
2. **VCmigrate**: Migrate from 32-bit process to 64-bit process using **Heaven's Gate**
3. **VCload**: Inject into the 32-bit process and perform Shellcode Reflective DLL Injection (**sRDI**) to do the migration and the password stealing

> A detailed blog post can be found here: [geobour98 Blog](https://geobour98.github.io/blog/veracrypt-stealer/)

## Disclaimer

This PoC was developed for **Educational** purposes only!