CTAP2_OK                            = b'\x00'   # Indicates successful response.
CTAP1_ERR_INVALID_LENGTH            = b'\x03'   # Invalid message or item length.
CTAP2_ERR_CBOR_UNEXPECTED_TYPE      = b'\x11'   # Invalid/unexpected CBOR error.
CTAP2_ERR_MISSING_PARAMETER         = b'\x14'   # Missing non-optional parameter.


class cb_int():
    def __init__(self, min_int, max_int):
        self.min_int = min_int
        self.max_int = max_int

    def verify(self, data):
        if not isinstance(data, int):
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE
        if data < self.min_int or data > self.max_int:
            return CTAP1_ERR_INVALID_LENGTH
        else:
            return CTAP2_OK


class cb_bool():
    def __init__(self, value):
        self.value = value

    def verify(self, data):
        if not isinstance(data, bool):
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE
        if self.value is not None:
            if data != self.value:
                return CTAP1_ERR_INVALID_LENGTH
        return CTAP2_OK


class cb_str():
    def __init__(self, min_len, max_len):
        self.min_len = min_len
        self.max_len = max_len

    def verify(self, data):
        if not isinstance(data, str):
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE
        if len(data) < self.min_len or len(data) > self.max_len:
            return CTAP1_ERR_INVALID_LENGTH
        else:
            return CTAP2_OK


class cb_bytes(cb_str):
    def verify(self, data):
        if not isinstance(data, bytes):
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE
        if len(data) < self.min_len or len(data) > self.max_len:
            return CTAP1_ERR_INVALID_LENGTH
        else:
            return CTAP2_OK


class cb_list():
    def __init__(self, min_len, max_len, element):
        self.min_len = min_len
        self.max_len = max_len
        self.element = element

    def verify(self, data):
        if not isinstance(data, list):
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE
        if len(data) < self.min_len or len(data) > self.max_len:
            return CTAP1_ERR_INVALID_LENGTH
        for d in data:
            ret = self.element.verify(d)
            if ret != CTAP2_OK:
                return ret
        return CTAP2_OK


class cb_map():
    def __init__(self, elements):
        # elements is list if dicts with keys: key, type, required
        self.elements = elements

    def verify(self, data):
        if not isinstance(data, dict):
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE
        for element in self.elements:
            if element['key'] in data:
                ret = element['type'].verify(data[element['key']])
                if ret != CTAP2_OK:
                    return ret
            else:
                if element['required'] is True:
                    return CTAP2_ERR_MISSING_PARAMETER
        return CTAP2_OK


PublicKeyCredentialRpEntity = cb_map([
    {'key': 'id', 'type': cb_str(1, 128), 'required': True},
    {'key': 'name', 'type': cb_str(1, 128), 'required': False},
    {'key': 'icon', 'type': cb_str(1, 128), 'required': False}
])

PublicKeyCredentialUserEntity = cb_map([
    {'key': 'id', 'type': cb_bytes(1, 128), 'required': True},
    {'key': 'name', 'type': cb_str(1, 128), 'required': False},
    {'key': 'displayName', 'type': cb_str(1, 128), 'required': False},
    {'key': 'icon', 'type': cb_str(1, 128), 'required': False}
])

PublicKeyCredentialType = cb_map([
    {'key': 'alg', 'type': cb_int(-65535, 65535), 'required': True},
    {'key': 'type', 'type': cb_str(1, 16), 'required': True},
])

pubKeyCredParams = cb_list(1, 16, PublicKeyCredentialType)

PublicKeyCredentialDescriptor = cb_map([
    {'key': 'type', 'type': cb_str(1, 64), 'required': True},
    {'key': 'id', 'type': cb_bytes(1, 512), 'required': True}
    # transports skipped
])

excludeList = cb_list(0, 100, PublicKeyCredentialDescriptor)

authenticatorMakeCredential_options = cb_map([
    {'key': 'rk', 'type': cb_bool(None), 'required': False},
    {'key': 'uv', 'type': cb_bool(None), 'required': False},
])


authenticatorMakeCredential = cb_map([
    {'key': 1, 'type': cb_bytes(32, 32), 'required': True},
    {'key': 2, 'type': PublicKeyCredentialRpEntity, 'required': True},
    {'key': 3, 'type': PublicKeyCredentialUserEntity, 'required': True},
    {'key': 4, 'type': pubKeyCredParams, 'required': True},
    {'key': 5, 'type': excludeList, 'required': False},
    {'key': 6, 'type': cb_map([]), 'required': False},
    {'key': 7, 'type': authenticatorMakeCredential_options, 'required': False},
    {'key': 8, 'type': cb_bytes(0, 16), 'required': False},
    {'key': 9, 'type': cb_int(1, 10), 'required': False}
])

authenticatorGetAssertion_options = cb_map([
    {'key': 'up', 'type': cb_bool(None), 'required': False},
    {'key': 'uv', 'type': cb_bool(None), 'required': False},
])

authenticatorGetAssertion = cb_map([
    {'key': 1, 'type': cb_str(1, 256), 'required': True},
    {'key': 2, 'type': cb_bytes(32, 32), 'required': True},
    {'key': 3, 'type': cb_list(0, 32, PublicKeyCredentialDescriptor),
     'required': False},
    {'key': 4, 'type': cb_map([]), 'required': False},
    {'key': 5, 'type': authenticatorGetAssertion_options, 'required': False},
    {'key': 6, 'type': cb_bytes(0, 16), 'required': False},
    {'key': 7, 'type': cb_int(1, 10), 'required': False}
])

platformKeyAgreementKey = cb_map([
    {'key': 1, 'type': cb_int(2, 2), 'required': True},  # kty: EC2 key type
    {'key': 3, 'type': cb_int(-25, -25), 'required': True},  # ECDH-ES+HKDF-256
    {'key': -1, 'type': cb_int(1, 1), 'required': True},  # crv: P-256
    {'key': -2, 'type': cb_bytes(32, 32), 'required': True},  # x-coord.
    {'key': -3, 'type': cb_bytes(32, 32), 'required': True},  # y-coord.
])

authenticatorClientPIN = cb_map([
    {'key': 1, 'type': cb_int(1, 1), 'required': True},
    {'key': 2, 'type': cb_int(1, 5), 'required': True},
    {'key': 3, 'type': platformKeyAgreementKey, 'required': False},
    {'key': 4, 'type': cb_bytes(16, 16), 'required': False},
    {'key': 5, 'type': cb_bytes(64, 64), 'required': False},
    {'key': 6, 'type': cb_bytes(16, 16), 'required': False},
])

credentialManagementSubCommandParams = cb_map([
    {'key': 1, 'type': cb_bytes(32, 32), 'required': False},  # rpIDHash
    {'key': 2, 'type': PublicKeyCredentialDescriptor, 'required': False},  # credentialID
])

authenticatorCredentialManagement = cb_map([
    {'key': 1, 'type': cb_int(1, 6), 'required': True},  # subCommand
    {'key': 2, 'type': credentialManagementSubCommandParams, 'required': False},  # subCommandParams
    {'key': 3, 'type': cb_int(1, 1), 'required': False},  # pinUvAuthProtocol
    {'key': 4, 'type': cb_bytes(16, 16), 'required': False},  # pinUvAuthParam
])

authenticatorGetAssertion_extension_hmac_secret = cb_map([
    {'key': 1, 'type': platformKeyAgreementKey, 'required': True},
    {'key': 2, 'type': cb_bytes(32, 64), 'required': True},  # one - or two saltEncs
    {'key': 3, 'type': cb_bytes(16, 16), 'required': True},  # pinUvAuthParam
])
