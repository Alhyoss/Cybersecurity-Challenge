
file = open("falsebinary", "r")
bits = file.read()
bits = bits.replace("p", "1").replace("o", "0")
print(bits)
f = open("binary", "w")
f.write(bits)