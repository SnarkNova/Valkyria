import os
import glob
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor

def genKey(password, salt=None):
    if salt is None:
        salt = get_random_bytes(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    return key, salt

def decrypt(key, encrypted):
    nonce = encrypted[:12]
    ciphertext = encrypted[12:-16]
    tag = encrypted[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def decryptFile(key, target):
    with open(target, "rb") as f:
        data = f.read()
    os.remove(target)
    salt = data[:16]
    encrypted = data[16:]
    key, _ = genKey(key, salt)
    decrypted = decrypt(key, encrypted)
    with open(target[:-9], "wb") as f:
        f.write(decrypted)

username = os.environ["USERNAME"]
target = f"C:\\Users\\{username}\\Desktop\\*"
extension = ["txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "jpg", "png", "csv", "sql", "mdb", "sln", "php", "asp", "aspx", "html", "xml", "psd"]
key = input("Input your decryption key: ")

for i in glob.glob(target):
    if not os.path.isdir(i) and i.endswith(".valkyria"):
        for j in extension:
            if i.split(".")[-2] == j:
                with ThreadPoolExecutor(max_workers=5) as executor:
                    executor.submit(decryptFile, key, i)
