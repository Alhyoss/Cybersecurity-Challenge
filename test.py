from utils import *

r = read_file("test").split("\n")
t = ""
for line in r:
    k = line.split(" ")
    k[0] = ""
    t += " ".join(k)

write_file("retest", t)