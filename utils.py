from base64 import *
import binascii


def encode_all(input, output="", printable=True):
    dict = {}
    dict["b64"] = apply_encode(input, output, False, b64encode)
    dict["b58"] = apply_encode(input, output, False, b58encode)
    dict["b32"] = apply_encode(input, output, False, b32encode)
    dict["b16"] = apply_encode(input, output, False, b16encode)
    string = ""
    for k, v in dict.items():
        string += k + ": " + str(v) + "\n"
    write_string(string, output, printable)
    return dict


def decode_all(input, output="", printable=True):
    dict = {}
    dict["b64"] = apply_decode(input, output, False, b64decode)
    dict["b58"] = apply_decode(input, output, False, b58decode)
    dict["b32"] = apply_decode(input, output, False, b32decode)
    dict["b16"] = apply_decode(input, output, False, b16decode)
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
    return apply_encode(input, output, printable, b16encode)

def decode_b64(input, output="", printable=True):
    return apply_decode(input, output, printable, b64decode)


def decode_b58(input, output="", printable=True):
    return apply_decode(input, output, printable, b58decode)


def decode_b32(input, output="", printable=True):
    return apply_decode(input, output, printable, b32decode)


def decode_b16(input, output="", printable=True):
    return apply_decode(input, output, printable, b16decode)


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


def get_string(input, output):
    if output == "":
        return input
    file = open(input, "r")
    try:
        string = file.read()
    except:
        file = open(input, "rb")
        string = file.read()
    file.close()
    return string


def write_string(string, output, printable):
    if output != "":
        file = open(output, "w")
        try:
            file.write(str(string))
        except:
            file = open(output, "wb")
            file.write(string)
        file.close()
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
    try:
        decoded = fun(string).decode("utf-8")
    except:
        try:
            decoded = fun(string)
        except:
            write_string("Unable to decode", output, printable)
            return "Unable to decode"
    write_string(decoded, output, printable)
    return decoded