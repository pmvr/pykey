from os import mkdir, remove, statvfs, rmdir
from storage import getmount
from binascii import hexlify, unhexlify
from cbor_io import decode, encode
from cc310 import sha256, random
from microcontroller import nvm
from io import BytesIO


class KS:
    def __init__(self):
        self.OFFSET = [0, 512]

    def parity(self, b):
        p = 0
        for x in b:
            p ^= x
        return p

    def load_keystore(self):
        # cbor-load keystore
        for index, offset in enumerate(self.OFFSET):
            b = nvm[offset: offset + 3]  # last byte is parity
            if b[0] ^ b[1] ^ b[2] != 0:
                continue
            L = (b[0] << 8) + b[1]
            if L == 0:
                continue
            try:
                b = nvm[offset + 3: offset + 3 + L + 1]  # last byte is parity
                if self.parity(b) != 0:
                    continue
                for x in b:
                    dict_kstore = decode(BytesIO(b[:-1]))
            except ValueError:
                continue
            except KeyError:
                continue
            if not isinstance(dict_kstore, dict):
                continue
            for k in dict_kstore:
                setattr(self, k, dict_kstore[k])
            for i in range(index):
                # restore backup
                nvm[self.OFFSET[i]: self.OFFSET[i] + 3 + L + 1] = nvm[self.OFFSET[index]: self.OFFSET[index] + 3 + len + 1]
            return True
        return False

    def save_keystore(self):
        # cbor-dump keystore
        dict_kstore = {}
        for m in self.__dict__.keys():
            dict_kstore[m] = getattr(self, m)
        fout = BytesIO()
        L = encode(dict_kstore, fout)
        Lb = bytearray(3)
        Lb[0], Lb[1] = (L >> 8) & 0xff, L % 0xff
        Lb[2] = Lb[0] ^ Lb[1]
        p = bytearray(1)
        p[0] = self.parity(fout.getvalue())
        for offset in self.OFFSET:
            nvm[offset: offset + 3 + L + 1] = Lb + fout.getvalue() + p

    def del_keystore(self):
        # delete all atributes
        offset = self.OFFSET
        for m in list(self.__dict__.keys()):
            delattr(self, m)
        self.OFFSET = offset

    def gen_new_keys(self):  # virtual method
        pass


class KS_CTAP2(KS):
    # Authenticator Attestation Globally Unique Identifier
    AAGUID = b'\xea>[P\xe6\xe8\xfb\xf4\xcc\xa7\xed\x19\xa6\x005\xa9'
    RK_DIR = 'rk_dir'
    RP = 'PublicKeyCredentialRpEntity'
    CONTENT = 'content'

    def __init__(self):
        self.OFFSET = [0, 512]
        if self.load_keystore() is False:
            self.gen_new_keys()
            self.save_keystore()

    def gen_new_keys(self):
        self.del_keystore()
        # hmac keys
        key = random(64)
        self.KEY_5C = bytes((k ^ 0x5c for k in key))
        self.KEY_36 = bytes((k ^ 0x36 for k in key))
        # AES key, IV
        self.AES_KEY = random(16)
        self.AES_IV = random(16)
        # delete all rk
        try:
            vfs = getmount('/')
            for x in vfs.ilistdir(KS_CTAP2.RK_DIR):
                for y in vfs.ilistdir(KS_CTAP2.RK_DIR + '/' + x[0]):
                    remove(KS_CTAP2.RK_DIR + '/' + x[0] + '/' + y[0])
                rmdir(KS_CTAP2.RK_DIR + '/' + x[0])
        except OSError:
            pass

    def get_number_rk_id(self, rkid, is_hash=False):
        if is_hash is False:
            hash_rkid = hexlify(sha256(rkid)).decode('utf8')
        else:
            hash_rkid = hexlify(rkid).decode('utf8')
        try:
            vfs = getmount('/')
            return max(0, sum(1 for _ in vfs.ilistdir(KS_CTAP2.RK_DIR + '/' + hash_rkid)) - 2)
        except OSError:
            return 0

    def get_total_number_rk(self):
        n = 0
        try:
            vfs = getmount('/')
            for x in vfs.ilistdir(KS_CTAP2.RK_DIR):
                n += max(0, sum(1 for _ in vfs.ilistdir(KS_CTAP2.RK_DIR + '/' + x[0])) - 2)
            return n
        except OSError:
            return 0

    def get_number_rk(self):
        n = 0
        try:
            vfs = getmount('/')
            for x in vfs.ilistdir(KS_CTAP2.RK_DIR):
                n += 1
            return n
        except OSError:
            return 0

    def get_number_free_rk(self):
        try:
            stat = statvfs('/flash')
            return max(0, (stat[0] * stat[3] - 20000) // 1000)
        except OSError:
            return 0

    def get_all_rp(self):
        try:
            vfs = getmount('/')
            for rpid in vfs.ilistdir(KS_CTAP2.RK_DIR):
                yield unhexlify(rpid[0])
        except OSError:
            return False
        return False

    def del_rk(self, rk_id, user_id):
        hash_rkid = sha256(rk_id)
        hash_user_id = sha256(user_id)[:16]
        if hash_rkid is None or hash_user_id is None:
            return False
        hash_rkid = hexlify(hash_rkid).decode('utf8')
        try:
            with open(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + KS_CTAP2.CONTENT, 'rb') as fin:
                content = fin.read()
            for i in range(0, len(content), 16):
                if content[i:i + 16] == hash_user_id:
                    size_content = 0
                    with open(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + KS_CTAP2.CONTENT, 'wb') as fout:
                        size_content += fout.write(content[:i])
                        size_content += fout.write(content[i + 16:])
                    fn = hexlify(hash_user_id).decode('utf8')
                    remove(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + fn)
                    # remove empty dir
                    if size_content == 0:
                        vfs = getmount('/')
                        for x in vfs.ilistdir(KS_CTAP2.RK_DIR + '/' + hash_rkid ):
                            remove(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + x[0])
                        rmdir(KS_CTAP2.RK_DIR + '/' + hash_rkid)
                    return True
        except OSError:
            return False
        return False

    def save_rk(self, rk, user_id, rk_data):
        try:
            stat = statvfs('/flash')
            if stat[0] * stat[3] < 20000:  # bsize * bfree
                # if actual number of free bytes too low exit
                return False
            try:
                mkdir(KS_CTAP2.RK_DIR)
            except OSError:
                pass
            hash_rkid = sha256(rk['id'])
            hash_user_id = sha256(user_id)[:16]
            if hash_rkid is None or hash_user_id is None:
                return False
            hash_rkid = hexlify(hash_rkid).decode('utf8')
            try:
                mkdir(KS_CTAP2.RK_DIR + '/' + hash_rkid)
            except OSError:
                pass
            try:
                with open(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + KS_CTAP2.CONTENT, 'rb') as fin:
                    content = fin.read()
            except OSError:
                content = b''
            for i in range(0, len(content), 16):
                if content[i:i + 16] == hash_user_id:
                    # most recent ones at the beginning
                    content = content[:i] + content[i + 16:]
                    break
            with open(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + KS_CTAP2.CONTENT, 'wb') as fout:
                # most recent ones at the beginning
                fout.write(hash_user_id)
                fout.write(content)
            fn = hexlify(hash_user_id).decode('utf8')
            with open(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + fn, 'wb') as fout:
                encode(rk_data, fout)
            with open(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + KS_CTAP2.RP, 'wb') as fout:
                encode(rk, fout)
        except OSError:
            return False
        except ValueError:
            return False
        return True

    def load_rk(self, rkid, is_hash=False):
        try:
            if is_hash is False:
                hash_rkid = hexlify(sha256(rkid)).decode('utf8')
            else:
                hash_rkid = hexlify(rkid).decode('utf8')
            with open(KS_CTAP2.RK_DIR + '/' + hash_rkid + '/' + KS_CTAP2.CONTENT, 'rb') as fin:
                while True:
                    hash_user_id = fin.read(16)
                    if len(hash_user_id) < 16:
                        break
                    fn = KS_CTAP2.RK_DIR + '/' + hash_rkid \
                        + '/' + hexlify(hash_user_id).decode('utf8')
                    # yield key_handle
                    with open(fn, 'rb') as rk_fin:
                        yield decode(rk_fin)
        except OSError:
            pass
        except ValueError:
            pass

    def load_user_information(self, rkid):
        rkid = hexlify(rkid).decode('utf8')
        try:
            with open(KS_CTAP2.RK_DIR + '/' + rkid + '/' + KS_CTAP2.RP, 'rb') as fin:
                return decode(fin)
        except OSError:
            return b''


class KS_PIN(KS):
    def __init__(self):
        self.OFFSET = [1024, 1024 + 512]
        if self.load_keystore() is False:
            self.gen_new_keys()
            self.save_keystore()

    def gen_new_keys(self):
        self.del_keystore()
        # PIN management
        self.PIN = b''
        self.PIN_DIGEST = b''
        self.PIN_MAX_RETRIES = 8
        self.PIN_RETRIES = self.PIN_MAX_RETRIES


class KS_U2F(KS):
    def __init__(self):
        self.OFFSET = [2048, 2048 + 512]
        if self.load_keystore() is False:
            self.gen_new_keys()
            self.save_keystore()

    def gen_new_keys(self):
        self.del_keystore()
        # hmac keys
        key = random(64)
        self.KEY_5C = bytes((k ^ 0x5c for k in key))
        self.KEY_36 = bytes((k ^ 0x36 for k in key))
        # AES key, IV
        self.AES_KEY = random(16)
        self.AES_IV = random(16)


class Counter():
    def __init__(self, offset):
        self.OFFSET = 3072 + offset
        self.load()

    def load(self):
        self.counter = int.from_bytes(bytes(nvm[self.OFFSET: self.OFFSET + 4]), 'big')

    def save(self):
        nvm[self.OFFSET: self.OFFSET + 4] = self.counter.to_bytes(4, 'big')

    def to_bytes(self):
        return bytes(nvm[self.OFFSET: self.OFFSET + 4])

    def inc(self):
        self.counter = (self.counter + 1) % 0x0100000000
        self.save()

    def reset(self):
        self.counter = 0
        self.save()
