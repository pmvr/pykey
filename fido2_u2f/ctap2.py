from time import monotonic
from board import LED2_R
from ctap_errors import *
from cc310 import sha256, hmac_sha256, ec_genkeypair, ec_sign, ec_dh, aes_cbc, aes256_cbc, random
from util import der_encode_signature, reboot_to_bootloader
from cbor_io import decode, encode
import cbor_ctap_parameters as ccp
from up_check import up_check
from keystore import KS_CTAP2, KS_PIN, Counter

# authenticator API: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api
authenticatorMakeCredential   = const(0x01)
authenticatorGetAssertion     = const(0x02)
authenticatorGetInfo          = const(0x04)
authenticatorClientPIN        = const(0x06)
authenticatorReset            = const(0x07)
authenticatorGetNextAssertion = const(0x08)
authenticatorCredentialManagement = const(0x0a)
authenticatorSelection        = const(0x0b)
authenticatorVendorFirst      = const(0x40)
authenticatorVendorLast       = const(0xbf)
authenticatorToBootloader     = authenticatorVendorFirst

# variables for managing next assertions
NUMBEROFCREDENTIALS = 0
CREDENTIALCOUNTER = 0
REM_GETASSERTION_PARAMETERS = []
REM_GETASSERTION_PARAMETERS_COMMON = []
REM_ITERATOR = None
REM_NUM_RESIDENTIAL_KEYS = 0
REM_LAST_CMD = None
NEXT_CREDENTIAL_TIMER = monotonic()

# PIN retry management
PIN_CONSECUTIVE_RETRIES = 0

# iterator list off relying parties (rp)
IT_LIST_RP = None
# iterator list of Public Key Credential User Entity
LIST_IT_KEYHANDLE = None

# keystores
ks_ctap2 = KS_CTAP2()
ks_pin = KS_PIN()
counter_fido2 = Counter(0)

# pinUvAuthToken
PIN_TOKEN = random(16)
# authenticatorKeyAgreementKey
DH_a = DH_aG = None

# timestamp for power up
POWER_UP = monotonic()


def ctap2(command, channel):
    global ks_ctap2, ks_pin, REM_LAST_CMD
    if len(command) == 0:
        return CTAP1_ERR_INVALID_LENGTH
    cmd, data = command[0], command[1:]
    REM_LAST_CMD = cmd
    if cmd == authenticatorGetInfo:
        if len(data) > 0:
            return CTAP1_ERR_INVALID_LENGTH
        return getInfo()
    elif cmd == authenticatorMakeCredential:
        if len(data) == 0:
            return CTAP1_ERR_INVALID_LENGTH
        return makeCredential(data, channel)
    elif cmd == authenticatorGetAssertion:
        if len(data) == 0:
            return CTAP1_ERR_INVALID_LENGTH
        return getAssertion(data, channel)
    elif cmd == authenticatorGetNextAssertion:
        if len(data) > 0:
            return CTAP1_ERR_INVALID_LENGTH
        return getNextAssertion(channel)
    elif cmd == authenticatorClientPIN:
        if len(data) == 0:
            return CTAP1_ERR_INVALID_LENGTH
        return clientPIN(data)
    elif cmd == authenticatorReset:
        if len(data) > 0:
            return CTAP1_ERR_INVALID_LENGTH
        return reset(channel)
    elif cmd == authenticatorCredentialManagement:
        if len(data) == 0:
            return CTAP1_ERR_INVALID_LENGTH
        return credentialManagement(data)
    elif cmd == authenticatorSelection:
        if len(data) > 0:
            return CTAP1_ERR_INVALID_LENGTH
        return selection()
    elif cmd == authenticatorToBootloader:
        if up_check(channel) != CTAP2_OK:
            return CTAP2_ERR_OPERATION_DENIED
        reboot_to_bootloader()
    else:
        return CTAP2_ERR_OPERATION_DENIED


def keepalive(channel):
    if channel.is_cancelled():
        return CTAP2_ERR_KEEPALIVE_CANCEL
    channel.keepalive(channel.STATUS_PROCESSING)
    return CTAP2_OK


def getInfo():
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
    global ks_ctap2
    return CTAP2_OK + encode({1: ['FIDO_2_0', 'FIDO_2_1_PRE', 'U2F_V2'],
                              2: ['credProtect', 'hmac-secret'],  # extensions
                              3: ks_ctap2.AAGUID,
                              4: {'rk': True,
                                  'clientPin': isPINset(),
                                  'credMgmt': True
                                  },
                              6: [1],  # pinUvAuthProtocols
                              7: 10,  # maxCredentialCountInList
                              8: 512,  # maxCredentialIdLength
                              })


def makeCredential(data, channel):
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
    global ks_ctap2, counter_fido2
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    try:
        data = decode(data)
    except ValueError:
        return CTAP2_ERR_INVALID_CBOR
    # verify structure of parameter for authenticatorMakeCredential
    ret = ccp.authenticatorMakeCredential.verify(data)
    if ret != CTAP2_OK:
        return ret
    # check if len(pinUvAuthParam) == 0 and pinUvAuthProtocol == 1
    ret = pin_check_steps_1_2(data, 8, 9)
    if ret != CTAP2_OK:
        return ret
    if not {'alg': -7, 'type': 'public-key'} in data[4]:  # only ES256
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM
    rk, uv = False, False  # default options
    if 7 in data:
        # If the options parameter is present, process all the options.
        rk = data[7].get('rk', False)
        uv = data[7].get('uv', False)
        if 'up' in data[7]:
            return CTAP2_ERR_INVALID_OPTION
        if uv is True:
            return CTAP2_ERR_UNSUPPORTED_OPTION
    FLAGS = 0  # ED | AT | 0 | 0 | 0 | uv | 0 | up
    FLAGS |= 0x40  # AT
    # build user description
    user_description = {'id': data[3]['id']}
    for key in ('displayName', 'name', 'icon'):
        if key in data[3]:
            user_description[key] = data[3][key]
    if 5 in data:   # excludeList
        for x in data[5]:
            if x['type'] != 'public-key':
                continue
            if dec_key_handle(x['id']) is not None:
                return CTAP2_ERR_CREDENTIAL_EXCLUDED
    credProtect = 1  # default value
    hmac_secret = False
    if 6 in data:  # extensions
        if 'credProtect' in data[6]:
            if data[6]['credProtect'] not in (1, 2, 3):
                return CTAP2_ERR_INVALID_OPTION
            credProtect = data[6]['credProtect']
            FLAGS |= 0x80  # ED
        if 'hmac-secret' in data[6]:
            if data[6]['hmac-secret'] not in (True, ):
                return CTAP2_ERR_INVALID_OPTION
            hmac_secret = True
            FLAGS |= 0x80  # ED
    if isPINset() is False and (8 in data or 9 in data):
        return CTAP2_ERR_UNSUPPORTED_OPTION
    if isPINset():
        if 8 not in data or 9 not in data:  # pinAuth
            return CTAP2_ERR_PIN_REQUIRED
        if verifyPIN(data[8], data[1]) is False:
            return CTAP2_ERR_PIN_AUTH_INVALID
        else:
            FLAGS |= 0x04  # uv
    # make credential
    # user presence check
    ret = up_check(channel)
    if ret == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    elif ret != CTAP2_OK:
        return CTAP2_ERR_OPERATION_DENIED
    FLAGS |= 1  # up
    # hash rpid
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    rp_id_hash = sha256(bytes(data[2]['id'], 'utf8'))
    if rp_id_hash is None:
        return CTAP1_ERR_OTHER  # error of nrf cryptocell
    # ec key genaration
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    ret = ec_genkeypair()
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    if ret is None:
        return CTAP1_ERR_OTHER  # error of nrf cryptocell
    d, Q = ret  # private key, public key
    cose_key = encode({1: 2,   # kty: EC2 key type
                       3: -7,  # alg: ES256 signature algorithm
                      -1: 1,   # crv: P-256 curve
                      -2: Q[1:1 + 32],  # x-coordinate
                      -3: Q[1 + 32:]    # y-coordinate
                       })
    # generate key handle
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    if hmac_secret is True:
        credRandom = random(64)
    else:
        credRandom = b''
    key_handle = enc_key_handle(d + encode({'id': data[2]['id'],
                                            'user': user_description,
                                            'credProtect': credProtect,
                                            'credRandom': credRandom}))
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    Lb = len(key_handle).to_bytes(2, 'big')
    # increase signature counter
    counter_fido2.inc()  # and store counter
    cb = counter_fido2.to_bytes()
    # authenticator data: https://www.w3.org/TR/webauthn/#fig-attStructs
    auth_data = rp_id_hash + FLAGS.to_bytes(1, 'big') + cb \
        + ks_ctap2.AAGUID + Lb + key_handle + cose_key
    # add extension field
    extension = {}
    if FLAGS & 0x80 > 0:
        extension['credProtect'] = credProtect
    if hmac_secret is True:
        extension['hmac-secret'] = True
    if extension:
        auth_data += encode(extension)
    # compute signature
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    ret = ec_sign(b'', auth_data + data[1])  # auth_data + client_data_hash
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    if ret is None:
        return CTAP1_ERR_OTHER  # error of nrf cryptocell
    signature = der_encode_signature(*ret)  # ret = r, s
    if rk is True:
        rk_data = {6: user_description,  # PublicKeyCredentialUserEntity
                   7: {'type': 'public-key', 'id': key_handle},  # credentialID
                   8: cose_key,  # publicKey
                   10: credProtect,  # credential protection policy
                   }
        storage = {'rk_data': rk_data}
        if ks_ctap2.save_rk(data[2], data[3]['id'], storage) is False:
            return CTAP2_ERR_KEY_STORE_FULL
        if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
            return CTAP2_ERR_KEEPALIVE_CANCEL

    # https://www.w3.org/TR/webauthn/#sctn-attestation
    try:
        with open('cert.der', 'rb') as fin:
            CERTIFICATE_DER = fin.read()
    except OSError:
        return CTAP1_ERR_OTHER
    return CTAP2_OK + encode({1: 'packed',
                              2: auth_data,
                              3: {'alg': -7,
                                  'sig': signature, 'x5c': [CERTIFICATE_DER]}
                              })


def getAssertion(data, channel):
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion
    global ks_ctap2, counter_fido2
    global NUMBEROFCREDENTIALS, CREDENTIALCOUNTER
    global REM_GETASSERTION_PARAMETERS, NEXT_CREDENTIAL_TIMER
    global REM_GETASSERTION_PARAMETERS_COMMON
    global REM_ITERATOR, REM_NUM_RESIDENTIAL_KEYS

    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    try:
        data = decode(data)
    except ValueError:
        return CTAP2_ERR_INVALID_CBOR
    # verify structure of parameter for authenticatorGetAssertion
    ret = ccp.authenticatorGetAssertion.verify(data)
    if ret != CTAP2_OK:
        return ret
    # check if len(pinUvAuthParam) == 0 and pinUvAuthProtocol == 1
    ret = pin_check_steps_1_2(data, 6, 7)
    if ret != CTAP2_OK:
        return ret
    # parse parameters
    # get options
    uv, up = False, True  # default options
    if 5 in data:   # Map of authenticator options
        if 'rk' in data[5]:
            return CTAP2_ERR_UNSUPPORTED_OPTION
        uv = data[5].get('uv', False)
        up = data[5].get('up', True)
        if uv is True:
            return CTAP2_ERR_UNSUPPORTED_OPTION
    # extensions
    hmac_secret = False
    if 4 in data:
        if 'hmac-secret' in data[4]:
            ret = ccp.authenticatorGetAssertion_extension_hmac_secret.verify(data[4]['hmac-secret'])
            if ret != CTAP2_OK:
                return ret
            if len(data[4]['hmac-secret'][2]) not in (32, 64):
                return CTAP1_ERR_INVALID_LENGTH
            hmac_secret = True
    if hmac_secret is True and up is False:
        return CTAP2_ERR_UNSUPPORTED_OPTION
    FLAGS = 0  # ED | AT | 0 | 0 | 0 | uv | 0 | up
    if isPINset(): # pinAuth
        if 6 not in data or 7 not in data:
            return CTAP2_ERR_PIN_REQUIRED
        if verifyPIN(data[6], data[2]) is False:
            return CTAP2_ERR_PIN_AUTH_INVALID
        else:
            FLAGS |= 0x04
    # user presence check
    if up is True:
        ret = up_check(channel)
        if ret == CTAP2_ERR_KEEPALIVE_CANCEL:
            return CTAP2_ERR_KEEPALIVE_CANCEL
        elif ret != CTAP2_OK:
            return CTAP2_ERR_OPERATION_DENIED
        FLAGS |= 1
    # locate all credentials that are eligible for retrieval under the specified criteria
    REM_GETASSERTION_PARAMETERS.clear()  # remember keys for next assertion
    REM_NUM_RESIDENTIAL_KEYS = 0
    REM_ITERATOR = None
    useRK = False  # indicate if key is residential key
    if 3 in data:   # allowList is present
        for pkc_descriptor in data[3]:
            if pkc_descriptor['type'] != 'public-key':
                continue
            if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
                return CTAP2_ERR_KEEPALIVE_CANCEL
            key_data = dec_key_handle(pkc_descriptor['id'])  # credId
            if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
                return CTAP2_ERR_KEEPALIVE_CANCEL
            if key_data is None:
                continue
            try:
                key_dict = decode(key_data[32:])
                rpId = key_dict['id']
                user_description = key_dict['user']
                credProtect = key_dict['credProtect']
                credRandom = key_dict['credRandom']
            except (ValueError, KeyError):
                continue
            if rpId != data[1]:
                continue  # rpId does not match
            if credProtect == 3 and FLAGS & 0x04 == 0:
                # userVerificationRequired but not done
                continue
            d = key_data[:32]
            REM_GETASSERTION_PARAMETERS.append([d, user_description, pkc_descriptor['id'], credRandom])
    else:
        # search for applicable residential keys
        for storage in ks_ctap2.load_rk(data[1]):
            rk_data = storage['rk_data']
            if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
                return CTAP2_ERR_KEEPALIVE_CANCEL
            if rk_data[0x0a] > 1 and FLAGS & 0x04 == 0:
                # userVerificationRequired but not done
                continue
            else:
                REM_NUM_RESIDENTIAL_KEYS += 1
        if REM_NUM_RESIDENTIAL_KEYS > 0:
            REM_ITERATOR = ks_ctap2.load_rk(data[1])
    if (not REM_GETASSERTION_PARAMETERS) and (REM_NUM_RESIDENTIAL_KEYS == 0):
        # no potential valid keys found at all
        return CTAP2_ERR_NO_CREDENTIALS
    # make assertion
    extension_hmac_secret = {}
    if REM_GETASSERTION_PARAMETERS:
        d, user_description, credentialID, credRandom = REM_GETASSERTION_PARAMETERS.pop()
    else:
        useRK = True
        while True:
            storage = REM_ITERATOR.__next__()
            rk_data = storage['rk_data']
            if rk_data[0x0a] > 1 and FLAGS & 0x04 == 0:
                # userVerificationRequired but not done
                continue
            else:
                credentialID = rk_data[7]['id']
                if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
                    return CTAP2_ERR_KEEPALIVE_CANCEL
                key_data = dec_key_handle(credentialID)
                if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
                    return CTAP2_ERR_KEEPALIVE_CANCEL
                if key_data is None:
                    return CTAP2_ERR_NOT_ALLOWED
                key_dict = decode(key_data[32:])
                user_description = key_dict['user']
                credRandom = key_dict['credRandom']
                d = key_data[:32]
                REM_NUM_RESIDENTIAL_KEYS -= 1
                break
    if hmac_secret is True and credRandom != b'':
        credRandom = credRandom[:32] if FLAGS & 0x04 > 0 else credRandom[32:]
        ret = genSharedSecret(channel, data[4]['hmac-secret'],
                              credRandom, extension_hmac_secret)
        if ret != CTAP2_OK:
            return ret
        FLAGS |= 0x80  # ED
    if FLAGS & 0x04 == 0:
        # uv=PIN not done: remove all optional user informations
        user_description = {'id': user_description['id']}
    NUMBEROFCREDENTIALS = 1 + len(REM_GETASSERTION_PARAMETERS) + REM_NUM_RESIDENTIAL_KEYS
    # rpIdHash
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    rp_id_hash = sha256(bytes(data[1], 'utf8'))
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    # increase signature counter
    counter_fido2.inc()  # and store counter
    cb = counter_fido2.to_bytes()
    # authenticator data: https://www.w3.org/TR/webauthn/#table-authData
    auth_data = rp_id_hash + FLAGS.to_bytes(1, 'big') + cb
    if extension_hmac_secret:
        # add hmac-secret extension
        auth_data += encode(extension_hmac_secret)
    # compute signature
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    ret = ec_sign(d, auth_data + data[2])  # auth_data + client_data_hash
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    if ret is None:
        return CTAP1_ERR_OTHER  # error of nrf cryptocell
    signature = der_encode_signature(*ret)  # ret = r,s
    if NUMBEROFCREDENTIALS > 1:
        REM_GETASSERTION_PARAMETERS_COMMON = [rp_id_hash, data[2], FLAGS, {}]
        if hmac_secret is True and 'hmac-secret' in storage:
            REM_GETASSERTION_PARAMETERS_COMMON[3] = data[4]['hmac-secret']
    CREDENTIALCOUNTER = 1
    NEXT_CREDENTIAL_TIMER = monotonic()  # start clock
    # https://www.w3.org/TR/webauthn/#sctn-attestation
    ret = {1: {'id': credentialID, 'type': 'public-key'},
           2: auth_data,
           3: signature}
    if useRK is True:
        ret[4] = user_description
    if NUMBEROFCREDENTIALS > 1:
        ret[5] = NUMBEROFCREDENTIALS
    return CTAP2_OK + encode(ret)


def getNextAssertion(channel):
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetNextAssertion
    global ks_ctap2, counter_fido2
    global NEXT_CREDENTIAL_TIMER, REM_GETASSERTION_PARAMETERS
    global CREDENTIALCOUNTER, NUMBEROFCREDENTIALS
    global REM_GETASSERTION_PARAMETERS_COMMON, REM_LAST_CMD
    global REM_ITERATOR, REM_NUM_RESIDENTIAL_KEYS

    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    if not REM_GETASSERTION_PARAMETERS and REM_NUM_RESIDENTIAL_KEYS == 0:
        return CTAP2_ERR_NOT_ALLOWED
    if REM_LAST_CMD not in(authenticatorGetAssertion, authenticatorGetNextAssertion):
        return CTAP2_ERR_NOT_ALLOWED
    if CREDENTIALCOUNTER >= NUMBEROFCREDENTIALS:
        return CTAP2_ERR_NOT_ALLOWED
    if monotonic() - NEXT_CREDENTIAL_TIMER > 30.0:
        return CTAP2_ERR_NOT_ALLOWED  # time out
    try:
        rp_id_hash, clientDataHash, FLAGS, hmac_secret = REM_GETASSERTION_PARAMETERS_COMMON
    except ValueError:
        return CTAP2_ERR_NOT_ALLOWED
    extension_hmac_secret = {}
    if REM_GETASSERTION_PARAMETERS:
        useRK = False
        d, user_description, credentialID, credRandom = REM_GETASSERTION_PARAMETERS.pop()
    else:
        # load next residential key
        useRK = True
        try:
            while True:
                storage = REM_ITERATOR.__next__()
                rk_data = storage['rk_data']
                if rk_data[0x0a] > 1 and FLAGS & 0x04 == 0:
                    # userVerificationRequired but not done
                    continue
                break
            credentialID = rk_data[7]['id']
            key_data = dec_key_handle(credentialID)
            if key_data is None:
                return CTAP2_ERR_NOT_ALLOWED
            key_dict = decode(key_data[32:])
            user_description = key_dict['user']
            credRandom = key_dict['credRandom']
            d = key_data[:32]
            REM_NUM_RESIDENTIAL_KEYS -= 1
        except (StopIteration, ValueError, AttributeError):
            REM_NUM_RESIDENTIAL_KEYS = 0
            return CTAP2_ERR_NOT_ALLOWED
    if hmac_secret and credRandom != b'':
        credRandom = credRandom[:32] if FLAGS & 0x04 > 0 else credRandom[32:]
        ret = genSharedSecret(
            channel, hmac_secret, credRandom, extension_hmac_secret)
        if ret != CTAP2_OK:
            return ret
        FLAGS |= 0x80  # ED

    if FLAGS & 0x04 == 0:
        # uv=PIN not done: remove all optional user informations
        user_description = {'id': user_description['id']}
    # increase signature counter
    counter_fido2.inc()  # and store counter
    # authenticator data: https://www.w3.org/TR/webauthn/#table-authData
    auth_data = rp_id_hash + FLAGS.to_bytes(1, 'big') + counter_fido2.to_bytes()
    if extension_hmac_secret:
        # add hmac-secret extension
        auth_data += encode(extension_hmac_secret)
    # compute signature
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    ret = ec_sign(d, auth_data + clientDataHash)  # auth_data + client_data_hash
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    if ret is None:
        return CTAP1_ERR_OTHER  # error of nrf cryptocell
    signature = der_encode_signature(*ret)  # ret = r,s
    CREDENTIALCOUNTER += 1
    NEXT_CREDENTIAL_TIMER = monotonic()  # start clock
    ret = {1: {'id': credentialID, 'type': 'public-key'},
           2: auth_data,
           3: signature}
    if useRK is True:
        ret[4] = user_description
    return CTAP2_OK + encode(ret)


def enc_key_handle(data):
    # add padding data 80 00 00 ...
    cipher = aes_cbc(data + b'\x80' + bytes(-(1 + len(data)) % 16),
                     ks_ctap2.AES_KEY, ks_ctap2.AES_IV, True)
    return cipher + hmac_sha256(ks_ctap2.KEY_5C, ks_ctap2.KEY_36, cipher)


def dec_key_handle(data):
    if len(data) < 64 or len(data) % 16 > 0:
        return None
    if data[-32:] != hmac_sha256(ks_ctap2.KEY_5C, ks_ctap2.KEY_36, data[:-32]):
        return None
    m = aes_cbc(data[:-32], ks_ctap2.AES_KEY, ks_ctap2.AES_IV, False)
    if m is None:
        return None
    # remove padding 80 00 00 ...
    for i in range(len(m) - 1, 31, -1):
        if m[i] == 0x80:
            return m[:i]
        elif m[i] == 0x00:
            continue
        else:
            return None  # wrong padding
    return None


def genSharedSecret(channel, hmac_secret, credRandom, extension_hmac_secret):
    # https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#sctn-hmac-secret-extension
    global DH_a, DH_aG
    x = hmac_secret[1][-2]
    y = hmac_secret[1][-3]
    Q = b'\x04' + bytes(-len(x) % 32) + x \
                + bytes(-len(y) % 32) + y
    # compute shared secret as SHA-256(Q.x)
    if DH_a is None or DH_aG is None:
        if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
            return CTAP2_ERR_KEEPALIVE_CANCEL
        DH_a, DH_aG = ec_genkeypair()
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    X = ec_dh(DH_a, Q)
    if X is None:
        return CTAP1_ERR_OTHER
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    shared_secret = sha256(X)
    if shared_secret is None:
        return CTAP1_ERR_OTHER
    k5c = bytes((c ^ 0x5c for c in shared_secret)) + b'\x5c' * 32
    k36 = bytes((c ^ 0x36 for c in shared_secret)) + b'\x36' * 32
    # The authenticator verifies saltEnc by generating
    # LEFT(HMAC-SHA-256(sharedSecret, saltEnc), 16) and matching against the
    # input saltAuth parameter.
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    if hmac_sha256(k5c, k36, hmac_secret[2])[:16] != hmac_secret[3]:
        return CTAP2_ERR_EXTENSION_FIRST
    # decrypt saltEnc
    salt = aes256_cbc(hmac_secret[2], shared_secret, bytes(16), False)
    # The authenticator generates one or two HMAC-SHA-256 values
    k5c = bytes((c ^ 0x5c for c in credRandom)) + b'\x5c' * 32
    k36 = bytes((c ^ 0x36 for c in credRandom)) + b'\x36' * 32
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    output1 = hmac_sha256(k5c, k36, salt[:32])
    if len(salt) == 64:
        output2 = hmac_sha256(k5c, k36, salt[32:])
        ext = aes256_cbc(output1 + output2, shared_secret, bytes(16), True)
    else:
        ext = aes256_cbc(output1, shared_secret, bytes(16), True)
    if keepalive(channel) == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    extension_hmac_secret['hmac-secret'] = ext
    return CTAP2_OK


def reset(channel):
    global PIN_CONSECUTIVE_RETRIES, ks_ctap2, ks_pin
    # user presence required
    #if monotonic() - POWER_UP > 10.0:
    #    return CTAP2_ERR_NOT_ALLOWED
    ret = up_check(channel, LED2_R)
    if ret == CTAP2_ERR_KEEPALIVE_CANCEL:
        return CTAP2_ERR_KEEPALIVE_CANCEL
    elif ret == CTAP2_ERR_USER_ACTION_TIMEOUT:
        return CTAP2_ERR_USER_ACTION_TIMEOUT
    PIN_CONSECUTIVE_RETRIES = 0
    ks_ctap2.gen_new_keys()
    ks_ctap2.save_keystore()
    ks_pin.gen_new_keys()
    ks_pin.save_keystore()
    counter_fido2.reset()
    return CTAP2_OK


def pin_check_steps_1_2(data, key_pin_auth, key_pin_prot):
    if key_pin_auth in data:
        if len(data[key_pin_auth]) == 0:
            # If authenticator supports clientPin and platform sends a zero
            # length pinUvAuthParam, wait for user touch and then return either
            # CTAP2_ERR_PIN_NOT_SET if pin is not set or CTAP2_ERR_PIN_INVALID
            # if pin has been set.
            ret = up_check(channel)
            if ret == CTAP2_OK:
                if isPINset() is False:
                    return CTAP2_ERR_PIN_NOT_SET
                else:
                    return CTAP2_ERR_PIN_INVALID
            else:
                return ret
    if key_pin_prot in data:
        if data[key_pin_prot] != 1:
            # If authenticator supports clientPin and pinUvAuthParam parameter
            # is present and the pinUvAuthProtocol is not supported,
            # return CTAP2_ERR_PIN_AUTH_INVALID error.
            return CTAP2_ERR_PIN_AUTH_INVALID
    return CTAP2_OK


def clientPIN(data):
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN
    global ks_pin, PIN_CONSECUTIVE_RETRIES, DH_a, DH_aG
    if DH_a is None or DH_aG is None:
        DH_a, DH_aG = ec_genkeypair()
        if DH_a is None or DH_aG is None:
            return CTAP1_ERR_OTHER
    try:
        data = decode(data)
    except ValueError:
        return CTAP2_ERR_INVALID_CBOR
    ret = ccp.authenticatorClientPIN.verify(data)
    if ret != CTAP2_OK:
        return ret
    if data[2] == 0x01:  # getRetries
        return CTAP2_OK + encode({3: ks_pin.PIN_RETRIES})
    elif data[2] == 0x02:  # getKeyAgreement
        return CTAP2_OK + encode({1: {1: 2,   # kty: EC2 key type
                                      3: -25,  # alg: ECDH-ES+HKDF-256
                                      -1: 1,   # crv: P-256 curve
                                      # x-coordinate
                                      -2: DH_aG[1: 1 + 32],
                                      # y-coordinate
                                      -3: DH_aG[32 + 1:]
                                      }
                                  })
    elif data[2] in (0x03, 0x04, 0x05):
        # verify parameters for setPIN, changePIN, getPINToken
        if 3 not in data:  # platformKeyAgreementKey
            return CTAP2_ERR_MISSING_PARAMETER
        if (data[2] in (0x03, 0x04)):
            if 4 not in data or 5 not in data:  # pinAuth, newPinEnc
                return CTAP2_ERR_MISSING_PARAMETER
        if (data[2] in (0x04, 0x05)):
            if 6 not in data:  # pinHashEnc
                return CTAP2_ERR_MISSING_PARAMETER
        if (data[2] == 0x03 and ks_pin.PIN != b'') \
           or (data[2] in (0x04, 0x05) and ks_pin.PIN == b''):
            # either setPIN command and PIN already set
            # or changePIN/getPINToken command and PIN not yet set
            return CTAP2_ERR_PIN_NOT_SET
        x = data[3][-2]
        y = data[3][-3]
        Q = b'\x04' + bytes(-len(x) % 32) + x \
                    + bytes(-len(y) % 32) + y
        # compute shared secret as SHA-256(Q.x)
        X = ec_dh(DH_a, Q)
        if X is None:
            return CTAP1_ERR_OTHER
        shared_secret = sha256(X)
        if shared_secret is None:
            return CTAP1_ERR_OTHER
        k5c = bytes((c ^ 0x5c for c in shared_secret)) + b'\x5c' * 32
        k36 = bytes((c ^ 0x36 for c in shared_secret)) + b'\x36' * 32
        if data[2] == 0x03:  # setPIN
            # Authenticator verifies pinAuth by generating
            # LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
            # and matching against input pinAuth parameter.
            if hmac_sha256(k5c, k36, data[5])[:16] != data[4]:
                return CTAP2_ERR_PIN_AUTH_INVALID
            # Authenticator decrypts newPinEnc using above "sharedSecret"
            # producing newPin and checks newPin length against minimum
            # PIN length of 4 bytes.
            return set_new_pin(shared_secret, data[5])
        elif data[2] == 0x04:  # changePIN
            # If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            if ks_pin.PIN_RETRIES == 0:
                return CTAP2_ERR_PIN_BLOCKED
            if PIN_CONSECUTIVE_RETRIES == 3:
                return CTAP2_ERR_PIN_AUTH_BLOCKED
            # Authenticator verifies pinAuth by generating
            # LEFT(HMAC-SHA-256(sharedSecret, newPinEnc || pinHashEnc), 16)
            # and matching against input pinAuth parameter.
            if hmac_sha256(k5c, k36, data[5] + data[6])[:16] != data[4]:
                return CTAP2_ERR_PIN_AUTH_INVALID
            # Authenticator decrements the retries counter by 1.
            ks_pin.PIN_RETRIES -= 1
            PIN_CONSECUTIVE_RETRIES += 1
            ks_pin.save_keystore()
            # Authenticator decrypts pinHashEnc and verifies against its
            # internal stored LEFT(SHA-256(curPin), 16).
            if len(data[6]) != 16:
                return CTAP1_ERR_OTHER
            dec = aes256_cbc(data[6], shared_secret, bytes(16), False)
            if dec != ks_pin.PIN_DIGEST:
                if ks_pin.PIN_RETRIES == 0:
                    return CTAP2_ERR_PIN_BLOCKED
                elif PIN_CONSECUTIVE_RETRIES == 3:
                    return CTAP2_ERR_PIN_AUTH_BLOCKED
                else:
                    return CTAP2_ERR_PIN_INVALID
            # Authenticator sets the retries counter to 8.
            ks_pin.PIN_RETRIES = ks_pin.PIN_MAX_RETRIES
            ks_pin.save_keystore()
            PIN_CONSECUTIVE_RETRIES = 0
            # Authenticator decrypts newPinEnc using above "sharedSecret"
            # producing newPin and checks newPin length against minimum
            # PIN length of 4 bytes.
            return set_new_pin(shared_secret, data[5])
        elif data[2] == 0x05:  # getPINToken
            # If the retries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            if ks_pin.PIN_RETRIES == 0:
                return CTAP2_ERR_PIN_BLOCKED
            if PIN_CONSECUTIVE_RETRIES == 3:
                return CTAP2_ERR_PIN_AUTH_BLOCKED
            # Authenticator decrements the retries counter by 1.
            ks_pin.PIN_RETRIES -= 1
            ks_pin.save_keystore()
            PIN_CONSECUTIVE_RETRIES += 1
            # Authenticator decrypts pinHashEnc and verifies against its
            # internal stored LEFT(SHA-256(curPin), 16).
            if len(data[6]) != 16:
                return CTAP1_ERR_OTHER
            dec = aes256_cbc(data[6], shared_secret, bytes(16), False)
            if dec != ks_pin.PIN_DIGEST:
                if ks_pin.PIN_RETRIES == 0:
                    return CTAP2_ERR_PIN_BLOCKED
                elif PIN_CONSECUTIVE_RETRIES == 3:
                    return CTAP2_ERR_PIN_AUTH_BLOCKED
                else:
                    return CTAP2_ERR_PIN_INVALID
            # Authenticator sets the retries counter to 8.
            ks_pin.PIN_RETRIES = ks_pin.PIN_MAX_RETRIES
            ks_pin.save_keystore()
            PIN_CONSECUTIVE_RETRIES = 0
            # Authenticator returns encrypted pinToken using
            # "sharedSecret": AES256-CBC(sharedSecret, IV=0, pinToken).
            pin_enc = aes256_cbc(PIN_TOKEN, shared_secret, bytes(16), True)
            if pin_enc is None:
                return CTAP1_ERR_OTHER
            return CTAP2_OK + encode({2: pin_enc})


def set_new_pin(shared_secret, newPinEnc):
    # https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN
    global ks_pin, PIN_CONSECUTIVE_RETRIES
    # Authenticator decrypts newPinEnc using above "sharedSecret"
    if len(newPinEnc) < 64 or len(newPinEnc) % 16 > 0:
        return CTAP1_ERR_OTHER
    pin = aes256_cbc(newPinEnc, shared_secret, bytes(16), False)
    if pin is None:
        return CTAP1_ERR_OTHER
    for i in range(len(pin) - 1, -1, -1):
        if pin[i] == 0:
            continue
        else:
            pin = pin[:i + 1]
            break
    if len(pin) < 4 or len(pin) > 63:
        return CTAP2_ERR_PIN_POLICY_VIOLATION
    # Authenticator stores LEFT(SHA-256(newPin), 16) on the device,
    # sets the retries counter to 8
    ks_pin.PIN_DIGEST = sha256(pin)[:16]
    ks_pin.PIN = pin
    ks_pin.PIN_RETRIES = ks_pin.PIN_MAX_RETRIES
    ks_pin.save_keystore()
    PIN_CONSECUTIVE_RETRIES = 0
    return CTAP2_OK


def isPINset():
    return ks_pin.PIN != b''


def verifyPIN(pinAuth, clientDataHash):
    n = -(len(PIN_TOKEN)) % 64
    k5c = bytes((c ^ 0x5c for c in PIN_TOKEN)) + b'\x5c' * n
    k36 = bytes((c ^ 0x36 for c in PIN_TOKEN)) + b'\x36' * n
    return hmac_sha256(k5c, k36, clientDataHash)[:16] == pinAuth


def credentialManagement(data):
    # https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorCredentialManagement
    global ks_ctap2, PIN_CONSECUTIVE_RETRIES, LIST_IT_RP, LIST_IT_KEYHANDLE
    if PIN_CONSECUTIVE_RETRIES == 3:
        return CTAP2_ERR_PIN_AUTH_BLOCKED
    try:
        data = decode(data)
    except ValueError:
        return CTAP2_ERR_INVALID_CBOR
    ret = ccp.authenticatorCredentialManagement.verify(data)
    if ret != CTAP2_OK:
        return ret
    if isPINset() is False:
        return CTAP2_ERR_PIN_AUTH_INVALID
    # check pin authentication
    if data[1] in (1, 2, 4, 6):
        PIN_CONSECUTIVE_RETRIES += 1
        if 3 not in data or 4 not in data:
            return CTAP2_ERR_MISSING_PARAMETER
        if data[3] != 1:
            return CTAP2_ERR_PIN_POLICY_VIOLATION
        if data[1] in (1, 2):
            verify = verifyPIN(data[4], encode(data[1]))
        elif data[1] in (4, 6):
            verify = verifyPIN(data[4], encode(data[1]) + encode(data[2]))
        if verify is False:
            if PIN_CONSECUTIVE_RETRIES == 3:
                return CTAP2_ERR_PIN_AUTH_BLOCKED
            return CTAP2_ERR_PIN_AUTH_INVALID
        PIN_CONSECUTIVE_RETRIES -= 1
    # parse subCommand
    if data[1] == 0x01:  # getCredsMetadata
        return CTAP2_OK + encode({1: ks_ctap2.get_total_number_rk(),
                                  2: ks_ctap2.get_number_free_rk()})
    elif data[1] == 0x02:  # enumerateRPsBegin
        num_rps = ks_ctap2.get_number_rk()
        if num_rps == 0:
            return CTAP2_ERR_NO_CREDENTIALS
        LIST_IT_RP = ks_ctap2.get_all_rp()  # iterator
        try:
            rp = LIST_IT_RP.__next__()
        except StopIteration:
            LIST_IT_RP = None
            return CTAP2_ERR_NO_CREDENTIALS
        return CTAP2_OK + encode({3: ks_ctap2.load_user_information(rp),
                                  4: rp,
                                  5: num_rps,
                                  })
    elif data[1] == 0x03:  # enumerateRPsGetNextRP
        if LIST_IT_RP is None:
            return CTAP2_ERR_NO_CREDENTIALS
        try:
            rp = LIST_IT_RP.__next__()
        except StopIteration:
            LIST_IT_RP = None
            return CTAP2_ERR_NO_CREDENTIALS
        return CTAP2_OK + encode({3: ks_ctap2.load_user_information(rp),
                                  4: rp,
                                  })
    elif data[1] == 0x04:  # enumerateCredentialsBegin
        if 2 not in data:
            return CTAP2_ERR_MISSING_PARAMETER
            if 1 not in data[2]:
                return CTAP2_ERR_MISSING_PARAMETER
        rpIDHash = data[2][1]
        num_rpIDHash = ks_ctap2.get_number_rk_id(rpIDHash, True)
        if num_rpIDHash == 0:
            return CTAP2_ERR_NO_CREDENTIALS
        LIST_IT_KEYHANDLE = ks_ctap2.load_rk(rpIDHash, True)
        try:
            storage = LIST_IT_KEYHANDLE.__next__()  # keys 6,7,8 already there
            rk_data = storage['rk_data']
        except StopIteration:
            LIST_IT_KEYHANDLE = None
            return CTAP2_ERR_NO_CREDENTIALS
        rk_data[9] = num_rpIDHash
        return CTAP2_OK + encode(rk_data)
    elif data[1] == 0x05:  # enumerateCredentialsGetNextCredential
        try:
            storage = LIST_IT_KEYHANDLE.__next__()  # keys 6,7,8 already there
            rk_data = storage['rk_data']
        except StopIteration:
            LIST_IT_KEYHANDLE = None
            return CTAP2_ERR_NO_CREDENTIALS
        return CTAP2_OK + encode(rk_data)
    elif data[1] == 0x06:  # deleteCredential
        if 2 not in data:
            return CTAP2_ERR_MISSING_PARAMETER
            if 2 not in data[2]:
                return CTAP2_ERR_MISSING_PARAMETER
        key_data = dec_key_handle(data[2][2]['id'])
        if key_data is None:
            return CTAP2_ERR_NO_CREDENTIALS
        try:
            key_dict = decode(key_data[32:])
            rpId = key_dict['id']
            user_description = key_dict['user']
        except (ValueError, KeyError):
            return CTAP2_ERR_NO_CREDENTIALS
        if ks_ctap2.del_rk(rpId, user_description['id']) is False:
            return CTAP2_ERR_NO_CREDENTIALS
        return CTAP2_OK


def selection():
    if up_check(channel, led_type=LED1) == CTAP2_ERR_USER_ACTION_TIMEOUT:
        return CTAP2_ERR_USER_ACTION_TIMEOUT
    return CTAP2_OK
