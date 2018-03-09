from base64 import b64decode
import pickle
import binascii

file = open("file", "r")

encoded = file.read()

newfile = open("bar.zip", "wb")

decoded = b64decode(encoded)

newfile.write(decoded)
