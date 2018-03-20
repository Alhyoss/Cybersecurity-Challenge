from base64 import *
import binascii


def read_file(input):
    try:
        file = open(input, "r")
        string = file.read()
    except:
        file = open(input, "rb")
        string = file.read()
    file.close()
    return string


def write_file(output, string):
    file = open(output, "w")
    try:
        file.write(str(string))
    except:
        file = open(output, "wb")
        file.write(string)
    file.close()


def appen_file(output, string):
    file = open(output, "a")
    try:
        file.write(string)
    except:
        file = open(output, "ab")
        file.write(string)
    file.close()


def encode_all(input, output="", printable=True):
    dict = {}
    dict["b64"] = encode_b64(input, output, False)
    dict["b58"] = encode_b58(input, output, False)
    dict["b32"] = encode_b32(input, output, False)
    dict["hex"] = encode_hex(input, output, False)
    dict["binary"] = encode_binary(input, output, False)
    string = ""
    for k, v in dict.items():
        string += k + ": " + str(v) + "\n"
    write_string(string, output, printable)
    return dict


def decode_all(input, output="", printable=True):
    dict = {}
    dict["b64"] = decode_b64(input, output, False)
    dict["b58"] = decode_b58(input, output, False)
    dict["b32"] = decode_b32(input, output, False)
    dict["hex"] = decode_hex(input, output, False)
    dict["binary"] = decode_binary(input, output, False)
    string = ""
    for k, v in dict.items():
        string += k + ": " + str(v) + "\n"
    write_string(string, output, printable)
    return dict


def encode_b64(input, output="", printable=True):
    return apply_encode(input, output, printable, b64encode)


def encode_b58(input, output="", printable=True):
    return apply_encode(input, output, printable, b58encode)


def encode_b32(input, output="", printable=True):
    return apply_encode(input, output, printable, b32encode)


def encode_b16(input, output="", printable=True):
    return encode_hex(input, output, printable)


def encode_hex(input, output="", printable=True):
    return apply_encode(input, output, printable, binascii.hexlify)


def encode_b2(input, output="", printable=True):
    return apply_encode(input, output, printable, b2encode)


def encode_binary(input, output="", printable=True):
    return apply_encode(input, output, printable, b2encode)


def decode_b64(input, output="", printable=True):
    return apply_decode(input, output, printable, b64decode)


def decode_b58(input, output="", printable=True):
    return apply_decode(input, output, printable, b58decode)


def decode_b32(input, output="", printable=True):
    return apply_decode(input, output, printable, b32decode)


def decode_b16(input, output="", printable=True):
    return decode_hex(input, output, printable)


def decode_hex(input, output="", printable=True):
    return apply_decode(input, output, printable, binascii.unhexlify)


def decode_b2(input, output="", printable=True):
    return decode_binary(input, output, printable)


def decode_binary(input, output="", printable=True):
    return apply_decode(input, output, printable, b2decode)

if bytes == str:  # python2
    iseq, bseq, buffer = (
		lambda s: map(ord, s),
		lambda s: ''.join(map(chr, s)),
		lambda s: s,
	)
else:  # python3
    iseq, bseq, buffer = (
		lambda s: s,
		bytes,
		lambda s: s.buffer,
	)

alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def scrub_input(string):
    if isinstance(string, str) and not isinstance(string, bytes):
        string = string.encode('ascii')
    if not isinstance(string, bytes):
        raise TypeError(
			"a bytes-like object is required (also str), not '%s'" %
			type(string).__name__)

    return string


def b58encode(string):
    def b58encode_int(i, default_one=True):
        if not i and default_one:
            return alphabet[0:1]
        string = b""
        while i:
            i, idx = divmod(i, 58)
            string = alphabet[idx:idx + 1] + string
        return string
    string = scrub_input(string)

    nPad = len(string)
    string = string.lstrip(b'\0')
    nPad -= len(string)

    p, acc = 1, 0
    for c in iseq(reversed(string)):
        acc += p * c
        p = p << 8

    result = b58encode_int(acc, default_one=False)

    return (alphabet[0:1] * nPad + result)


def b2encode(string):
    bytes = ""
    for c in string:
        b = format(ord(c), "b")
        bytes += b if len(b) == 8 else "0"*(8-len(b)) + b
    return bytes


def b58decode(string):
    def b58decode_int(string):
        string = scrub_input(string)

        decimal = 0
        for char in string:
            decimal = decimal * 58 + alphabet.index(char)
        return decimal
    string = scrub_input(string)

    origlen = len(string)
    string = string.lstrip(alphabet[0:1])
    newlen = len(string)

    acc = b58decode_int(string)

    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)
    return (b'\0' * (origlen - newlen) + bseq(reversed(result)))


def b2decode(string):
    n = int(string, 2)
    return binascii.unhexlify("%x" % n)


def get_string(input, output):
    if output == "":
        return input
    return read_file(input)


def write_string(string, output, printable):
    if output != "":
        write_file(output, string)
    if printable:
        print(string)


def apply_encode(input, output, printable, fun):
    string = get_string(input, output)
    try:
        encoded = fun(string).decode("utf-8")
    except:
        encoded = fun(string.encode("utf-8")).decode("utf-8")
    write_string(encoded, output, printable)
    return encoded


def apply_decode(input, output, printable, fun):
    string = get_string(input, output)
    decoded = ""
    lines = string.split("\n")
    for line in lines:
        try:
            decoded += fun(line).decode("utf-8")
        except:
            try:
                decoded += fun(line)
            except Exception as e:
                write_string("Unable to decode: " + str(e), output, printable)
                return "Unable to decode"
    write_string(decoded, output, printable)
    return decoded

x = encode_b58("comment???")

decode_b58(x)