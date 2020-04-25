from micropython import const
from board import LED2_R
from cc310 import hmac_sha256, ec_genkeypair, ec_sign, aes_cbc
from util import der_encode_signature
from keystore import KS_U2F, Counter
from up_check import u2f_up_check

SW_NO_ERROR                 = b'\x90\x00'
SW_CONDITIONS_NOT_SATISFIED = b'\x69\x85'
SW_WRONG_DATA               = b'\x6a\x80'
SW_WRONG_LENGTH             = b'\x67\x00'
SW_CLA_NOT_SUPPORTED        = b'\x6e\x00'
SW_INS_NOT_SUPPORTED        = b'\x6d\x00'
SW_COMMAND_ABORTED          = b'\x6f\x00'

UP_CHECK_OK = b'\x00'

KEY_HANDLE_LENGTH = const(64)

ks_u2f = KS_U2F()
counter_u2f = Counter(4)


def u2f(apdu):
    global ks_u2f
    if len(apdu) < 4:
        return SW_WRONG_LENGTH
    cmd, ins, p1, _ = apdu[0], apdu[1], apdu[2], apdu[3]  # p2 unconsidered
    lc = le = 0
    req = b''

    if len(apdu) == 5:
        le = apdu[4]
    elif len(apdu) == 6:
        if apdu[4] == 1:
            lc = 1
            req = apdu[5:]
        else:
            le = apdu[4] * 256 + apdu[5] if apdu[4] | apdu[5] > 0 else 2**16
    elif len(apdu) > 6:
        if apdu[4] > 0:
            lc = apdu[4]
            req, rest = apdu[5:5 + lc], apdu[5 + lc:]
            if len(req) != lc:
                return SW_WRONG_LENGTH
            if len(rest) == 1:
                le = rest[0] if rest[0] > 0 else 256
            elif len(rest) > 1:
                return SW_WRONG_LENGTH
        else:
            lc = apdu[5] * 256 + apdu[6]
            req, rest = apdu[7:7 + lc], apdu[7 + lc:]
            if len(req) != lc:
                return SW_WRONG_LENGTH
            if len(rest) == 2:
                if rest[0] | rest[1] > 0:
                    le = rest[0] * 256 + rest[1]  # however, le is never used
                else:
                    le = 2**16  # le not used
            elif len(rest) > 2:
                return SW_WRONG_LENGTH

    if cmd != 0:
        return SW_CLA_NOT_SUPPORTED
    elif ins == 1:
        return u2f_register(req)
    elif ins == 2:
        return u2f_authenticate(p1, req)
    elif ins == 3:
        # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#other-messages
        return b'U2F_V2' + SW_NO_ERROR
    elif ins == 0xc0:  # U2F_VENDOR_FIRST
        # reset U2F device = generate new keys
        if u2f_up_check(LED2_R) != UP_CHECK_OK:
            return SW_CONDITIONS_NOT_SATISFIED
        ks_u2f.gen_new_keys()
        ks_u2f.save_keystore()
        counter_u2f.reset()
        return SW_NO_ERROR
    else:
        return SW_INS_NOT_SUPPORTED


def u2f_register(req):
    # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-messages
    if len(req) != 64:
        return SW_WRONG_LENGTH
    if u2f_up_check() != UP_CHECK_OK:
        return SW_CONDITIONS_NOT_SATISFIED
    # ec key genaration
    d, user_public_key = ec_genkeypair()
    key_handle = enc_key_handle(d, req[32:])
    if key_handle is None:
        return SW_COMMAND_ABORTED  # error of nrf cryptocell

    message = b'\x00' + req[32:] + req[:32] + key_handle + user_public_key
    ret = ec_sign(b'', message)
    if ret is None:
        return SW_COMMAND_ABORTED  # error of nrf cryptocell
    signature = der_encode_signature(*ret)  # ret = r,s
    try:
        with open('cert.der', 'rb') as fin:
            CERTIFICATE_DER = fin.read()
    except OSError:
        return SW_COMMAND_ABORTED
    return b'\x05' \
           + user_public_key \
           + KEY_HANDLE_LENGTH.to_bytes(1, 'big') \
           + key_handle \
           + CERTIFICATE_DER \
           + signature \
           + SW_NO_ERROR


def u2f_authenticate(control_byte, req):
    # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#authentication-messages
    global ks_u2f, counter_u2f
    L = req[64]
    if L != KEY_HANDLE_LENGTH:
        return SW_WRONG_DATA
    if len(req) != 64 + 1 + L:
        return SW_CONDITIONS_NOT_SATISFIED
    if control_byte not in (0x03, 0x07, 0x08):
        return SW_CONDITIONS_NOT_SATISFIED
    key_handle = dec_key_handle(req[65:], req[32:64])
    if key_handle is None:
        return SW_WRONG_DATA
    if control_byte == 0x07:  # check-only
        return SW_CONDITIONS_NOT_SATISFIED
    user_presemce = b'\x00'
    if control_byte == 0x03:  # enforce-user-presence-and-sign
        if u2f_up_check() != UP_CHECK_OK:
            return SW_CONDITIONS_NOT_SATISFIED
        user_presemce = b'\x01'
    private_key = key_handle[:32]
    counter_u2f.inc()  # and save counter
    cb = counter_u2f.to_bytes()
    message = req[32:64] + user_presemce + cb + req[:32]
    ret = ec_sign(private_key, message)
    if ret is None:
        return SW_COMMAND_ABORTED  # error of nrf cryptocell
    signature = der_encode_signature(*ret)  # ret = r,s
    return user_presemce + cb + signature + SW_NO_ERROR


def enc_key_handle(data, appl_parameter):
    global ks_u2f
    cipher = aes_cbc(data, ks_u2f.AES_KEY, ks_u2f.AES_IV, True)
    mac = hmac_sha256(ks_u2f.KEY_5C, ks_u2f.KEY_36, cipher + appl_parameter)
    if cipher is None or mac is None:
        return None
    return cipher + mac


def dec_key_handle(data, application_parameter):
    global ks_u2f
    if len(data) != KEY_HANDLE_LENGTH:
        return None
    if data[-32:] != hmac_sha256(ks_u2f.KEY_5C, ks_u2f.KEY_36,
                                 data[:-32] + application_parameter):
        return None
    # decrypt key handle
    return aes_cbc(data[:32], ks_u2f.AES_KEY, ks_u2f.AES_IV, False)
