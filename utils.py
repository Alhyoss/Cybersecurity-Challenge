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


def append_file(output, string):
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

file = "1f620e09863c3d9321492c06096b3e492012489b3b5dc03d3d6d305d082d5d9e2148301109a21158d93309a22a1f5817580f13484d0a58e535097f0e091d1304e70609ba0e16031809ab1b589b0e4817395d782f040e124961231f8a3e49100958a11e58cc0904e6004933003d7a2a4881251fc30b191f325d7f3609e00f097400487e0b04350e1f96215dfe1d49342904b42909753358f93858c43158d401048520048e352e140e09dc0e5dd03158a0331f5437584208485c1458a02d3d742a5d91363d8d1b3d660704a62f2e2f283d66025885351f603e4918092e083709d13209630d58c80158f730095c2749523e1f822a04db024915020938052e182f49310409630d09e4265dfa03489408044217099a174859163d530d58690758471e041027488b143dae151f841a1f1e3804350d5dd0015d623858872c5d9e211f15235d5233042e3d588b125de7294813394858373d1125042c145d973b3d891848252f1f88023dac0209e10a04f60958011f58f5312e18323d38391f791c5854035d292858241409490a580f0104f13658e12904e73548733d5d56295d201404fd1f09882304321d2e1f3449762b09ae1848041e04d72604b3231f4f1e09452049741b58d00709be2c04b80f5db22e58b30e04c610040e125dc73b5dd91c58e1001f2e0858210b0455011f831904471d09a3243d2a0a04592b0948114965383d2b3358b32e48812558210b09ed1f097c04492c06496c20482c021fd7101fa119494f1a49220b48043158a432487333495c053d751c1fac205ded1004ca1509a32d584e225dc81b04653a5802353d8d1b5d03381f1f2c4820135d1d225d81123da3285d56195d3c04048b2e5dc3015d5d384861385876071fc43004241704d3381f5a2b3d080904c31f099d2d04663758183e58f70a580b0658d92e58e6082e211c04e934193e1016040304012119061048552c09903158b31904142a48213d09701d3d0b075824143d3d3c1f3c2b5d0d2e3d581309cc131f5e1858692e1f29220454105daa1604cd2f493e1e040c3b04702a3d391e58ee1348281c04d30e58b82d48581f58592e193e0c046408160620584c305d8c1404f42f04c90509e23004d30e493a012e391704ce071f1e1f58c1375d6c1e09eb1e58293209ac3958f234096b0004d03358b52f094e222e182f1fac20493d3d5d5f3a5dfe1d047b1a1f0312585a0258992c3daa1849673e09d6003da30e58482e588e113d192b4952343da40509612958083719311e09a41a2e201c5831132e202909b8104873224846175d8c285d721f5dac265de00909340a58223c58653e5891093d5733484422497811497b0904ac225db93809173b3da8295d9e051fa8132e2f32484f28048b2b042f120970355d4d0f3d9a040908161f1e30048102092e085dc41704622404e42e1f2f015dee1c485506094d3d09b6074919151f742d0992342e1214580c06584a2004901209e52e2e202748570858b40c04ff061f2d0409be2c4857083da4152e082b19292009943b19092f3d1f151f6227098e1a496b00192f0809df145d991f3d19390966190952041921291f061b1fcb2f48251004940309233a1f213858212948360a1fc23e160b083d9b2f584f19046c0b5d56193d391e1f312c482510097e173d8e02190615097309485e2d584e221fae3b49602c04453c09ca1258c62a48170404482758f6213d203858f622496e120943125d14243d7639094e035d4b2458c62c58690716012b1feb1b1fac305839351f5e185dc3015859171fb13958082909ea02094f211f933409943b58cc091f753c04ec1a4964091f0b1549170a048c214869303d3f23093106097e171f10335d53302e1e254825101f0a203da41c496809496f1c5d830f1fd42f58022f58680d5d0e24047b3209272258ab23097e1a04532b5d9b144939095d162609bf1e1fbf1204f30a04db0204ee2f4808354973345d9b3e485f2a58210409c514042030042a3e48201f48902c58b0285d570f5d9f045d58091f4f093d660758982e1fb82209e72f585c3e1fe51d09371c5d593c2e200c040334192116"
out = "2018/cooldown/forensics/magic_zip/out.zip"

decode_hex(file)
