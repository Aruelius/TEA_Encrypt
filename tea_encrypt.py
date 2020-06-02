import ctypes
import base64
import random

import rsa


def int_overflow(val):
    maxint = 2147483647
    if not -maxint-1 <= val <= maxint:
        val = (val + (maxint + 1)) % (2 * (maxint + 1)) - maxint - 1
    return val

def uor(n,i):
    if n<0:
        n = ctypes.c_uint32(n).value
    if i<0:
        return -int_overflow(n << abs(i))
    return int_overflow(n >> i)

class TEA(object):
    f, _, m, dollar, v, y, w, k, b = "", 0, [], [], 0, 0, [], [], True
    @staticmethod
    def e():
        return round(random.random() * 4294967295)
    
    @staticmethod
    def i(t, e, i):
        if not i or i > 4:
            i = 4
        n = 0
        for o in range(e, e + i):
            n <<= 8
            n |= t[o]
        return uor(4294967295 & n, 0)

    @staticmethod
    def n(t, e, i):
        t[e + 3] = i >> 0 & 255
        t[e + 2] = i >> 8 & 255
        t[e + 1] = i >> 16 & 255
        t[e + 0] = i >> 24 & 255

    @staticmethod
    def o(t):
        if not t:
            return ""
        e = ""
        for i in range(len(t)):
            n = hex(int(t[i]))[2:]
            if 1 == len(n):
                n = "0" + n
            e += n
        return e

    @staticmethod
    def p(t):
        e = ""
        for i in range(len(t), 2):
            e += chr(int(t[i:i+2], 16))
        return e

    @staticmethod
    def strToBytes(t, e):
        def _init():
            [i.append(ii[_]) for _ in sorted(ii)]
        if not t:
            return ""
        if e:
            t = TEA.s(t)
        i, ii = [], {}
        for n in range(len(t)):
            ii[n] = ord(t[n])
        _init()
        return TEA.o(i)

    @staticmethod
    def s(t):
        n = []
        o = len(t)
        for e in range(o):
            i = ord(t[e])
            if i > 0 and i <= 127:
                n.append(t[e])
            elif i >= 128 and i <= 2047:
                n.append(chr(192 | i >> 6 & 31)+chr(128 | 63 & i))
            elif i >= 2048 and i <= 65535:
                n.append(chr(224 | i >> 12 & 15)+chr(128 | i >> 6 & 63)+chr(128 | 63 & i))
        return "".join(n)

    @staticmethod
    def a(t):
        TEA.m = [__ for __ in range(8)]
        TEA.dollar = [__ for __ in range(8)]
        TEA.v = TEA.y = 0
        TEA.b = True
        TEA._ = 0
        i = len(t)
        n = 0
        TEA._ = (i + 10) % 8
        if 0 != TEA._:
            TEA._ = 8 - TEA._
        TEA.w = [__ for __ in range(i + TEA._ + 10)]
        TEA.m[0] = 255 & (248 & TEA.e() | TEA._)
        for o in range(1, TEA._+1):
            TEA.m[o] = 255 & TEA.e()
        TEA._ += 1
        for o in range(8):
            TEA.dollar[o] = 0
        n = 1
        while n <= 2:
            if TEA._ < 8:
                TEA.m[TEA._] = 255 & TEA.e()
                TEA._ += 1
                n += 1
            if 8 == TEA._:
                TEA.c()
        o = 0
        while i > 0:
            if TEA._ < 8:
                TEA.m[TEA._] = t[o]
                TEA._ += 1
                o += 1
                i -= 1
            if 8 == TEA._:
                TEA.c()
        n = 1
        while n <= 7:
            if TEA._ < 8:
                TEA.m[TEA._] = 0
                TEA._ += 1
                n += 1
            if 8 == TEA._:
                TEA.c()
        return TEA.w

    @staticmethod
    def l(t):
        e = 0
        i = [__ for __ in range(8)]
        n = len(t)
        TEA.k = t
        if n % 8 != 0 or n < 16:
            return None
        TEA.dollar = TEA.g(t)
        TEA._ = 7 & TEA.dollar[0]
        e = n - TEA._ - 10
        if e < 0:
            return None
        for o in range(len(i)):
           i[o] = 0
        TEA.w = [__ for __ in range(e)]
        TEA.y = 0
        TEA.v = 8
        TEA._ += 1
        p = 1
        while p <= 2:
            if TEA._ < 8:
                TEA._ += 1
                p += 1
            if 8 == TEA._:
                i = t
                if not TEA.d():
                    return None
        o = 0
        while 0 != e:
            if TEA._ < 8:
                TEA.w[o] = 255 & (i[TEA.y + TEA._] ^ TEA.dollar[TEA._])
                o += 1
                e -= 1
                TEA._ += 1
            if 8 == TEA._:
                i = t
                TEA.y = TEA.v - 8
                if not TEA.d():
                    return None
        for p in range(1, 8):
            if TEA._ < 8:
                if 0 != (i[TEA.y + TEA._] ^ TEA.dollar[TEA._]):
                    return None
                TEA._ += 1
            if 8 == TEA._:
                i = t
                TEA.y = TEA.v
                if not TEA.d():
                    return None
        return TEA.w

    @staticmethod
    def c():
        for t in range(8):
            TEA.m[t] ^= TEA.dollar[t] if TEA.b else TEA.w[TEA.y + t]
        e = TEA.u(TEA.m)
        for t in range(8):
            TEA.w[TEA.v + t] = e[t] ^ TEA.dollar[t]
            TEA.dollar[t] = TEA.m[t]
        TEA.y = TEA.v
        TEA.v += 8
        TEA._ = 0
        TEA.b = False

    @staticmethod
    def u(t):
        e = 16
        o = TEA.i(t, 0, 4)
        p = TEA.i(t, 4, 4)
        r = TEA.i(TEA.f, 0, 4)
        s = TEA.i(TEA.f, 4, 4)
        a = TEA.i(TEA.f, 8, 4)
        l = TEA.i(TEA.f, 12, 4)
        c = 0
        while e > 0:
            c += 2654435769
            c = uor(4294967295 & c, 0)
            o += (p << 4) + r ^ p + c ^ uor(p, 5) + s
            o = uor(4294967295 & o, 0)
            p += (o << 4) + a ^ o + c ^ uor(o, 5) + l
            p = uor(4294967295 & p, 0)
            e -= 1
        u = [__ for __ in range(8)]
        TEA.n(u, 0, o)
        TEA.n(u, 4, p)
        return u

    @staticmethod
    def g(t):
        e = 16
        o = TEA.i(t, 0, 4)
        p = TEA.i(t, 4, 4)
        r = TEA.i(TEA.f, 0, 4)
        s = TEA.i(TEA.f, 4, 4)
        a = TEA.i(TEA.f, 8, 4)
        l = TEA.i(TEA.f, 12, 4)
        c = 3816266640
        while e > 0:
            p -= (o << 4) + a ^ o + c ^ uor(o, 5) + l
            p = (4294967295 & p, 0)
            o -= (p << 4) + r ^ p + c ^ uor(p, 5) + s
            o = uor(4294967295 & o, 0)
            c -= 2654435769
            c = (4294967295 & c, 0)
            e -= 1
        u = [__ for __ in range(8)]
        TEA.n(u, 0, o)
        TEA.n(u, 4, p)
        return u

    @staticmethod
    def d():
        for t in range(8):
            TEA.dollar[t] ^= TEA.k[TEA.v + t]
        TEA.dollar = TEA.g(TEA.dollar)
        TEA.v += 8
        TEA._ = 0
        return True

    @staticmethod
    def h(t):
        def _init():
            [i.append(ii[_]) for _ in sorted(ii)]
        i, ii = [], {}
        o = 0
        for n in range(0, len(t), 2):
            ii[o] = int(t[n:n+2], 16)
            o += 1
        _init()
        return i

    @staticmethod
    def encrypt(t):
        return TEA.o(TEA.a(TEA.h(t)))

    @staticmethod
    def initkey(t):
        TEA.f = TEA.h(t)

class Encryption(object):
    _, m, v = 1, 8, 32
    @staticmethod
    def t(t):
        return Encryption.e(t)

    @staticmethod
    def e(t):
        return Encryption.u(Encryption.i(Encryption.c(t), len(t) * Encryption.m))

    @staticmethod
    def i(t, e):
        def _init():
            [t.append(tt[_]) for _ in sorted(tt)]
        tt = {}
        for i in range((14 + (uor(e + 64, 9) << 4)) + 1):
            try:
                tt[i] = t[i]
            except IndexError:
                tt[i] = 0
        t = []
        _init()
        t[e >> 5] |= 128 << e % 32
        t[14 + (uor(e + 64, 9) << 4)] = e
        i = 1732584193
        n = -271733879
        l = -1732584194
        c = 271733878
        for u in range(0, len(t), 16):
            g, d, h, f = i, n, l, c
            i = Encryption.o(i, n, l, c, t[u + 0], 7, -680876936)
            c = Encryption.o(c, i, n, l, t[u + 1], 12, -389564586)
            l = Encryption.o(l, c, i, n, t[u + 2], 17, 606105819)
            n = Encryption.o(n, l, c, i, t[u + 3], 22, -1044525330)
            i = Encryption.o(i, n, l, c, t[u + 4], 7, -176418897)
            c = Encryption.o(c, i, n, l, t[u + 5], 12, 1200080426)
            l = Encryption.o(l, c, i, n, t[u + 6], 17, -1473231341)
            n = Encryption.o(n, l, c, i, t[u + 7], 22, -45705983)
            i = Encryption.o(i, n, l, c, t[u + 8], 7, 1770035416)
            c = Encryption.o(c, i, n, l, t[u + 9], 12, -1958414417)
            l = Encryption.o(l, c, i, n, t[u + 10], 17, -42063)
            n = Encryption.o(n, l, c, i, t[u + 11], 22, -1990404162)
            i = Encryption.o(i, n, l, c, t[u + 12], 7, 1804603682)
            c = Encryption.o(c, i, n, l, t[u + 13], 12, -40341101)
            l = Encryption.o(l, c, i, n, t[u + 14], 17, -1502002290)
            n = Encryption.o(n, l, c, i, 0, 22, 1236535329)
            i = Encryption.p(i, n, l, c, t[u + 1], 5, -165796510)
            c = Encryption.p(c, i, n, l, t[u + 6], 9, -1069501632)
            l = Encryption.p(l, c, i, n, t[u + 11], 14, 643717713)
            n = Encryption.p(n, l, c, i, t[u + 0], 20, -373897302)
            i = Encryption.p(i, n, l, c, t[u + 5], 5, -701558691)
            c = Encryption.p(c, i, n, l, t[u + 10], 9, 38016083)
            l = Encryption.p(l, c, i, n, 0, 14, -660478335)
            n = Encryption.p(n, l, c, i, t[u + 4], 20, -405537848)
            i = Encryption.p(i, n, l, c, t[u + 9], 5, 568446438)
            c = Encryption.p(c, i, n, l, t[u + 14], 9, -1019803690)
            l = Encryption.p(l, c, i, n, t[u + 3], 14, -187363961)
            n = Encryption.p(n, l, c, i, t[u + 8], 20, 1163531501)
            i = Encryption.p(i, n, l, c, t[u + 13], 5, -1444681467)
            c = Encryption.p(c, i, n, l, t[u + 2], 9, -51403784)
            l = Encryption.p(l, c, i, n, t[u + 7], 14, 1735328473)
            n = Encryption.p(n, l, c, i, t[u + 12], 20, -1926607734)
            i = Encryption.r(i, n, l, c, t[u + 5], 4, -378558)
            c = Encryption.r(c, i, n, l, t[u + 8], 11, -2022574463)
            l = Encryption.r(l, c, i, n, t[u + 11], 16, 1839030562)
            n = Encryption.r(n, l, c, i, t[u + 14], 23, -35309556)
            i = Encryption.r(i, n, l, c, t[u + 1], 4, -1530992060)
            c = Encryption.r(c, i, n, l, t[u + 4], 11, 1272893353)
            l = Encryption.r(l, c, i, n, t[u + 7], 16, -155497632)
            n = Encryption.r(n, l, c, i, t[u + 10], 23, -1094730640)
            i = Encryption.r(i, n, l, c, t[u + 13], 4, 681279174)
            c = Encryption.r(c, i, n, l, t[u + 0], 11, -358537222)
            l = Encryption.r(l, c, i, n, t[u + 3], 16, -722521979)
            n = Encryption.r(n, l, c, i, t[u + 6], 23, 76029189)
            i = Encryption.r(i, n, l, c, t[u + 9], 4, -640364487)
            c = Encryption.r(c, i, n, l, t[u + 12], 11, -421815835)
            l = Encryption.r(l, c, i, n, 0, 16, 530742520)
            n = Encryption.r(n, l, c, i, t[u + 2], 23, -995338651)
            i = Encryption.s(i, n, l, c, t[u + 0], 6, -198630844)
            c = Encryption.s(c, i, n, l, t[u + 7], 10, 1126891415)
            l = Encryption.s(l, c, i, n, t[u + 14], 15, -1416354905)
            n = Encryption.s(n, l, c, i, t[u + 5], 21, -57434055)
            i = Encryption.s(i, n, l, c, t[u + 12], 6, 1700485571)
            c = Encryption.s(c, i, n, l, t[u + 3], 10, -1894986606)
            l = Encryption.s(l, c, i, n, t[u + 10], 15, -1051523)
            n = Encryption.s(n, l, c, i, t[u + 1], 21, -2054922799)
            i = Encryption.s(i, n, l, c, t[u + 8], 6, 1873313359)
            c = Encryption.s(c, i, n, l, 0, 10, -30611744)
            l = Encryption.s(l, c, i, n, t[u + 6], 15, -1560198380)
            n = Encryption.s(n, l, c, i, t[u + 13], 21, 1309151649)
            i = Encryption.s(i, n, l, c, t[u + 4], 6, -145523070)
            c = Encryption.s(c, i, n, l, t[u + 11], 10, -1120210379)
            l = Encryption.s(l, c, i, n, t[u + 2], 15, 718787259)
            n = Encryption.s(n, l, c, i, t[u + 9], 21, -343485551)
            i = Encryption.a(i, g),
            n = Encryption.a(n, d),
            l = Encryption.a(l, h),
            c = Encryption.a(c, f)
        array = []
        if 16 == Encryption.v:
            array.append(n)
            array.append(l)
        else:
            array.append(i[0])
            array.append(n[0])
            array.append(l[0])
            array.append(c)
        return array

    @staticmethod
    def n(t, e, i, n, o, p):
        return Encryption.a(Encryption.l(Encryption.a(Encryption.a(e, t), Encryption.a(n, p)), o), i)

    @staticmethod
    def o(t, e, i, o, p, r, s):
        return Encryption.n(e & i | ~e & o, t, e, p, r, s)
    
    @staticmethod
    def p(t, e, i, o, p, r, s):
        return Encryption.n(e & o | i & ~o, t, e, p, r, s)
    
    @staticmethod
    def r(t, e, i, o, p, r, s):
        return Encryption.n(e ^ i ^ o, t, e, p, r, s)

    @staticmethod
    def s(t, e, i, o, p, r, s):
        return Encryption.n(i ^ (e | ~o), t, e, p, r, s)

    @staticmethod
    def a(t, e):
        i = (65535 & t) + (65535 & e)
        return int_overflow(int_overflow(t >> 16) + int_overflow(e >> 16) + int_overflow(i >> 16) << 16) | 65535 & i
    
    @staticmethod
    def l(t, e):
        return t << e | uor(t, 32 - e)
    
    @staticmethod
    def c(t):
        def _init():
            [e.append(ee[_]) for _ in sorted(ee)]
        e, ee = [], {}
        i = (1 << Encryption.m) - 1
        for n in range(0, Encryption.m * len(t), Encryption.m):
            ee[n >> 5] = ee.get(n >> 5, 0) | ord(t[(n // Encryption.m) & i]) << n % 32
            # ee[n >> 5] |= ord(t[(n // Encryption.m) & i]) << n % 32
        _init()
        return e
    
    @staticmethod
    def u(t):
        e = "0123456789ABCDEF" if Encryption._ else "0123456789abcdef"
        i = ""
        for n in range(4 * len(t)):
            i += e[t[n >> 2] >> n % 4 * 8 + 4 & 15] + e[t[n >> 2] >> n % 4 * 8 & 15]
        return i

    @staticmethod
    def g(t):
        e = []
        for i in range(0, len(t), 2):
            e.append(chr(int(t[i:i+2], 16)))
        return "".join(e)

    @staticmethod
    def rsa_encrypt(data):
        exponent = int("10001", 16)
        modulus = int("e9a815ab9d6e86abbf33a4ac64e9196d5be44a09bd0ed6ae052914e1a865ac8331fed863de8ea697e9a7f63329e5e23cda09c72570f46775b7e39ea9670086f847d3c9c51963b131409b1e04265d9747419c635404ca651bbcbc87f99b8008f7f5824653e3658be4ba73e4480156b390bb73bc1f8b33578e7a4e12440e9396f2552c1aff1c92e797ebacdc37c109ab7bce2367a19c56a033ee04534723cc2558cb27368f5b9d32c04d12dbd86bbd68b1d99b7c349a8453ea75d1b2e94491ab30acf6c46a36a75b721b312bedf4e7aad21e54e9bcbcf8144c79b6e3c05eb4a1547750d224c0085d80e6da3907c3d945051c13c7c1dcefd6520ee8379c4f5231ed", 16)
        pub_key = rsa.PublicKey(modulus, exponent)
        encrypt_data = rsa.encrypt(data.encode("latin1"), pub_key)
        return encrypt_data[0].hex()

    @staticmethod
    def getEncryption(e, i , n, o=""):
        tea = TEA()
        n = n or ""
        e = e or ""
        p = e if o else Encryption.t(e)
        r = Encryption.g(p)
        s = Encryption.t(r + i)
        a = tea.strToBytes(n.upper(), True)
        l = str(len(a) // 2)
        while len(l) < 4:
            l = "0" + l
        tea.initkey(s)
        c = tea.encrypt(p + TEA.strToBytes(i, False) + l + a)
        tea.initkey("")
        u = hex(len(c) // 2)[2:]
        while len(u) < 4:
            u = "0" + u
        h = Encryption.rsa_encrypt(Encryption.g(u + c))
        password = base64.b64encode(
            Encryption.g(h).encode('latin1')
        ).decode("utf-8").replace("/", "-").replace("+", "*").replace("=", "_")
        return password

def get_salt(qq: int):
    maxLength = 16
    qq_hex = hex(qq)[2:]
    qq_len = len(qq_hex)

    for _ in range(qq_len, maxLength):
        qq_hex = "0" + qq_hex
    arr = []
    for j in range(0, maxLength, 2):
        arr.append(chr(int("0x" + qq_hex[j: j+2], 16)))
    result = "".join(arr)
    return result

if __name__ == "__main__":
    qq = 123456
    password = "qq123456"
    vcode = "!c96" # 通过滑动验证之后取得的验证码
    print(Encryption.getEncryption(password, get_salt(qq), vcode))
