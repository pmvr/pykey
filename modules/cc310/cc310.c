#include "crys_hash.h"
#include "crys_ecpki_types.h"
#include "crys_ecpki_kg.h"
#include "crys_ecpki_ecdsa.h"
#include "crys_ecpki_dh.h"
#include "crys_ecpki_domain.h"
#include "crys_ecpki_build.h"
#include "crys_aesccm.h"
#include "sns_silib.h"
#include "aes.h"

#include "py/obj.h"
#include "py/runtime.h"
#include "py/builtin.h"
#include "py/objarray.h"
#include <stdio.h>
#include <string.h>

// This is the function which will be called from Python 
STATIC mp_obj_t cc310_sha256(mp_obj_t message) {
    uint32_t ret=0;
    CRYS_HASH_Result_t hashOutBuff;
    mp_buffer_info_t message_info;
    
    mp_get_buffer_raise(message, &message_info, MP_BUFFER_READ);
    
    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
    // enable CryptoCell hardware
    NRF_CRYPTOCELL->ENABLE = 1;
    ret = SaSi_LibInit();
    if (ret != 0) return mp_const_none;
    ret = CRYS_HASH(CRYS_HASH_SHA256_mode, message_info.buf, message_info.len, hashOutBuff);
    // disable CryptoCell hardware
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
    NRF_CRYPTOCELL->ENABLE = 0;
    SaSi_LibFini();
    if (ret != 0) return mp_const_none;

    // return 32-Byte hash value
    mp_obj_t *hash = MP_OBJ_TO_PTR(mp_obj_new_bytes((uint8_t*)hashOutBuff, 32));
    return hash;
}
// Define a Python reference to the function above
STATIC MP_DEFINE_CONST_FUN_OBJ_1(cc310_sha256_obj, cc310_sha256);

// This is the function which will be called from Python 
STATIC mp_obj_t cc310_hmac_sha256(mp_obj_t key_5c, mp_obj_t key_36, mp_obj_t message) {
    uint32_t ret=0;
    CRYS_HASHUserContext_t ContextID;
    CRYS_HASH_Result_t hashOutBuff;
    mp_buffer_info_t buffer_info;
    
    mp_get_buffer_raise(key_36, &buffer_info, MP_BUFFER_READ);
    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
    // enable CryptoCell hardware
    NRF_CRYPTOCELL->ENABLE = 1;
    ret = SaSi_LibInit();
    if (ret != 0) return mp_const_none;
    //ret = CRYS_RndInit(&rndState_ptr, &rndWorkBuff_ptr);
    //if (ret != 0) return mp_const_none;
    ret = CRYS_HASH_Init(&ContextID, CRYS_HASH_SHA256_mode);
    if (ret != 0) return mp_const_none;
    ret = CRYS_HASH_Update(&ContextID, buffer_info.buf, buffer_info.len);
    if (ret != 0) return mp_const_none;
    mp_get_buffer_raise(message, &buffer_info, MP_BUFFER_READ);
    ret = CRYS_HASH_Update(&ContextID, buffer_info.buf, buffer_info.len);
    if (ret != 0) return mp_const_none;
    ret = CRYS_HASH_Finish(&ContextID, hashOutBuff);
    if (ret != 0) return mp_const_none;
    mp_get_buffer_raise(key_5c, &buffer_info, MP_BUFFER_READ);
    ret = CRYS_HASH_Init(&ContextID, CRYS_HASH_SHA256_mode);
    if (ret != 0) return mp_const_none;
    ret = CRYS_HASH_Update(&ContextID, buffer_info.buf, buffer_info.len);
    if (ret != 0) return mp_const_none;
    ret = CRYS_HASH_Update(&ContextID, (uint8_t*)hashOutBuff, 32);
    if (ret != 0) return mp_const_none;
    ret = CRYS_HASH_Finish(&ContextID, hashOutBuff);
    if (ret != 0) return mp_const_none;
    // disable CryptoCell hardware
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
    NRF_CRYPTOCELL->ENABLE = 0;
    SaSi_LibFini();
    //ret = CRYS_RND_UnInstantiation(&rndState_ptr);
    //if (ret != 0) return mp_const_none;

    // return 32-Byte hash value
    mp_obj_t *hash = MP_OBJ_TO_PTR(mp_obj_new_bytes((uint8_t*)hashOutBuff, 32));
    return hash;
}
// Define a Python reference to the function above
STATIC MP_DEFINE_CONST_FUN_OBJ_3(cc310_hmac_sha256_obj, cc310_hmac_sha256);

// This is the function which will be called from Python 
STATIC mp_obj_t cc310_ec_genkeypair(void) {
    uint32_t ret=0;
    const CRYS_ECPKI_Domain_t *pDomain;
    CRYS_ECPKI_UserPrivKey_t UserPrivKey;
    CRYS_ECPKI_UserPublKey_t UserPublKey;
    CRYS_ECPKI_KG_TempData_t TempECCKGBuff;
    CRYS_ECPKI_KG_FipsContext_t FipsBuff;
    SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc = CRYS_RND_GenerateVector;
    CRYS_RND_State_t rndState;
    CRYS_RND_WorkBuff_t rndWorkBuff;

    
    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
    // enable CryptoCell hardware
    NRF_CRYPTOCELL->ENABLE = 1;
    ret = SaSi_LibInit();
    if (ret != 0) return mp_const_none;
    ret = CRYS_RndInit(&rndState, &rndWorkBuff);
    if (ret != 0) return mp_const_none;
    pDomain = CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
    ret = CRYS_ECPKI_GenKeyPair (&rndState,
                rndGenerateVectFunc,
				pDomain,
				&UserPrivKey,
				&UserPublKey,
				&TempECCKGBuff,
                &FipsBuff);
    if (ret != 0) return mp_const_none;
    // disable CryptoCell hardware
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
    NRF_CRYPTOCELL->ENABLE = 0;
    SaSi_LibFini();
    ret = CRYS_RND_UnInstantiation(&rndState);
    if (ret != 0) return mp_const_none;

    // export key pair
    uint8_t privkey[32];
    uint32_t size_privkey = 32;
    ret = CRYS_ECPKI_ExportPrivKey(&UserPrivKey, privkey, &size_privkey);
    if (ret != 0) return mp_const_none;
    uint8_t pubkey[65];
    uint32_t size_pubkey = 65;
    ret = CRYS_ECPKI_ExportPublKey(&UserPublKey, CRYS_EC_PointUncompressed, pubkey, &size_pubkey);
    if (ret != 0) return mp_const_none;
    // retrun key pair as tuple (private key, public key)
    mp_obj_t keypair[2];
    keypair[0] = mp_obj_new_bytes(privkey, sizeof(privkey));
    keypair[1] = mp_obj_new_bytes(pubkey, sizeof(pubkey));
    return mp_obj_new_tuple(2, keypair);
}
// Define a Python reference to the function above
STATIC MP_DEFINE_CONST_FUN_OBJ_0(cc310_ec_genkeypair_obj, cc310_ec_genkeypair);

// This is the function which will be called from Python 
STATIC mp_obj_t cc310_ec_sign(mp_obj_t privkey, mp_obj_t message) {
    uint32_t ret=0;
    const CRYS_ECPKI_Domain_t *pDomain;
    CRYS_ECPKI_UserPrivKey_t UserPrivKey;
    CRYS_ECDSA_SignUserContext_t SignUserContext;
    uint8_t signature[64];
    uint32_t len_signature = sizeof(signature);
    SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc = CRYS_RND_GenerateVector;
    CRYS_RND_State_t rndState;
    CRYS_RND_WorkBuff_t rndWorkBuff;
    mp_buffer_info_t privkey_info;
    mp_buffer_info_t message_info;


    mp_get_buffer_raise(privkey, &privkey_info, MP_BUFFER_READ);
    mp_get_buffer_raise(message, &message_info, MP_BUFFER_READ);
    
    pDomain = CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
    if (privkey_info.len == 0) {
        privkey_info.buf = (uint8_t*)(0xfd7e0);
        privkey_info.len = 32;
    }
    ret = CRYS_ECPKI_BuildPrivKey(pDomain, privkey_info.buf, privkey_info.len, &UserPrivKey);
    if (ret != 0) return mp_const_none;

    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
    // enable CryptoCell hardware
    NRF_CRYPTOCELL->ENABLE = 1;
    ret = SaSi_LibInit();
    if (ret != 0) return mp_const_none;
    ret = CRYS_RndInit(&rndState, &rndWorkBuff);
    if (ret != 0) return mp_const_none;
    ret = CRYS_ECDSA_Sign (&rndState,
                rndGenerateVectFunc,
                &SignUserContext,
                &UserPrivKey,
                CRYS_ECPKI_HASH_SHA256_mode,
                message_info.buf,
                message_info.len,
                signature,
                &len_signature);
    if (ret != 0) return mp_const_none;
    // disable CryptoCell hardware
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
    NRF_CRYPTOCELL->ENABLE = 0;
    SaSi_LibFini();
    ret = CRYS_RND_UnInstantiation(&rndState);
    if (ret != 0) return mp_const_none;

    // return (r,s) in big endian
    mp_obj_t rs[2];
    rs[0] = mp_obj_new_bytes(signature, 32);
    rs[1] = mp_obj_new_bytes(signature+32, 32);
    return mp_obj_new_tuple(2, rs);
}
// Define a Python reference to the function above
STATIC MP_DEFINE_CONST_FUN_OBJ_2(cc310_ec_sign_obj, cc310_ec_sign);

// This is the function which will be called from Python 
STATIC mp_obj_t cc310_ec_dh(mp_obj_t privkey, mp_obj_t pubkey) {
    uint32_t ret=0;
    const CRYS_ECPKI_Domain_t *pDomain;
    CRYS_ECPKI_UserPrivKey_t UserPrivKey;
    CRYS_ECPKI_UserPublKey_t UserPublKey;
    CRYS_ECPKI_BUILD_TempData_t TempBuff;
    CRYS_ECDH_TempData_t TempDHBuff;
    uint8_t sharedSecret[32];
    uint32_t size_sharedSecret = sizeof(sharedSecret);
    mp_buffer_info_t privkey_info;
    mp_buffer_info_t pubkey_info;


    mp_get_buffer_raise(privkey, &privkey_info, MP_BUFFER_READ);
    mp_get_buffer_raise(pubkey, &pubkey_info, MP_BUFFER_READ);
    
    pDomain = CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
    ret = CRYS_ECPKI_BuildPrivKey(pDomain, privkey_info.buf, privkey_info.len, &UserPrivKey);
    if (ret != 0) return mp_const_none;
    ret = _DX_ECPKI_BuildPublKey(pDomain, pubkey_info.buf, pubkey_info.len, ECpublKeyPartlyCheck, &UserPublKey, &TempBuff);
    if (ret != 0) return mp_const_none;

    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
    // enable CryptoCell hardware
    NRF_CRYPTOCELL->ENABLE = 1;
    ret = SaSi_LibInit();
    if (ret != 0) return mp_const_none;
    ret = CRYS_ECDH_SVDP_DH (&UserPublKey,
                &UserPrivKey,
                sharedSecret,
                &size_sharedSecret,
                &TempDHBuff);
    if (ret != 0) return mp_const_none;
    // disable CryptoCell hardware
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
    NRF_CRYPTOCELL->ENABLE = 0;
    SaSi_LibFini();

    // return common secret
    mp_obj_t *x = MP_OBJ_TO_PTR(mp_obj_new_bytes(sharedSecret, size_sharedSecret));
    return x;
}
// Define a Python reference to the function above
STATIC MP_DEFINE_CONST_FUN_OBJ_2(cc310_ec_dh_obj, cc310_ec_dh);

// This is the function which will be called from Python 
STATIC mp_obj_t cc310_aes_cbc(size_t n_args, const mp_obj_t *args) {
    //mp_obj_t message, mp_obj_t key, mp_obj_t iv, mp_obj_t enc_dec_mode
    uint32_t ret=0;
    SaSiAesUserContext_t ContextID;
    SaSiAesUserKeyData_t keyData;
    mp_buffer_info_t message_info;
    mp_buffer_info_t key_info;
    mp_buffer_info_t iv_info;
    CRYS_RND_State_t rndState;
    CRYS_RND_WorkBuff_t rndWorkBuff;
    mp_obj_t cipher;
    mp_buffer_info_t cipher_info;
    uint8_t mode;
    
    mp_get_buffer_raise(args[0], &message_info, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &key_info, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &iv_info, MP_BUFFER_READ);
    
    if (mp_obj_is_true(args[3])) mode = SASI_AES_ENCRYPT;
    else                              mode = SASI_AES_DECRYPT;
    
    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
    // enable CryptoCell hardware
    NRF_CRYPTOCELL->ENABLE = 1;
    ret = SaSi_LibInit();
    if (ret != 0) return mp_const_none;
    ret = CRYS_RndInit(&rndState, &rndWorkBuff);
    if (ret != 0) return mp_const_none;
    
    ret = SaSi_AesInit(&ContextID, mode, SASI_AES_MODE_CBC,  SASI_AES_PADDING_NONE);
    if (ret != 0) return mp_const_none;
    ret = SaSi_AesSetIv(&ContextID, iv_info.buf);
    if (ret != 0) return mp_const_none;
    keyData.pKey = key_info.buf;
    keyData.keySize = key_info.len;
    ret = SaSi_AesSetKey(&ContextID, SASI_AES_USER_KEY, &keyData, sizeof(keyData));
    if (ret != 0) return mp_const_none;
    cipher = mp_obj_new_bytes_of_zeros(message_info.len);
    mp_get_buffer_raise(cipher, &cipher_info, MP_BUFFER_READ);
    for (uint16_t block_index = 0; block_index<message_info.len/SASI_AES_BLOCK_SIZE_IN_BYTES; block_index++) {
        ret = SaSi_AesBlock(&ContextID,
            message_info.buf + (block_index*SASI_AES_BLOCK_SIZE_IN_BYTES),
            SASI_AES_BLOCK_SIZE_IN_BYTES,
            cipher_info.buf + (block_index*SASI_AES_BLOCK_SIZE_IN_BYTES));
        if (ret != 0) return mp_const_none;
    }
    // disable CryptoCell hardware
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
    NRF_CRYPTOCELL->ENABLE = 0;
    SaSi_LibFini();
    if (ret != 0) return mp_const_none;
    ret = CRYS_RND_UnInstantiation(&rndState);
    if (ret != 0) return mp_const_none;

    // return cipher
    return MP_OBJ_TO_PTR(cipher);
}
// Define a Python reference to the function above
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(cc310_aes_cbc_obj, 4, 4, cc310_aes_cbc);

// This is the function which will be called from Python 
STATIC mp_obj_t cc310_aes256_cbc(size_t n_args, const mp_obj_t *args) {
    //mp_obj_t message, mp_obj_t key, mp_obj_t iv, mp_obj_t enc_dec_mode
    mp_buffer_info_t message_info;
    mp_buffer_info_t key_info;
    mp_buffer_info_t iv_info;
    mp_obj_t cipher;
    mp_buffer_info_t cipher_info;
    struct AES_ctx ctx;
    
    mp_get_buffer_raise(args[0], &message_info, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &key_info, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &iv_info, MP_BUFFER_READ);
    cipher = mp_obj_new_bytes_of_zeros(message_info.len);
    mp_get_buffer_raise(cipher, &cipher_info, MP_BUFFER_READ);
    
    memcpy(cipher_info.buf, message_info.buf, message_info.len);
    AES_init_ctx_iv(&ctx, key_info.buf, iv_info.buf);
    if (mp_obj_is_true(args[3])) AES_CBC_encrypt_buffer(&ctx, cipher_info.buf, cipher_info.len);
    else                         AES_CBC_decrypt_buffer(&ctx, cipher_info.buf, cipher_info.len);
    
    // return cipher
    return MP_OBJ_TO_PTR(cipher);
}
// Define a Python reference to the function above
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(cc310_aes256_cbc_obj, 4, 4, cc310_aes256_cbc);


// This is the function which will be called from Python 
STATIC mp_obj_t cc310_random(mp_obj_t size_in) {
    uint32_t ret=0;
    CRYS_RND_State_t rndState;
    CRYS_RND_WorkBuff_t rndWorkBuff;
    mp_obj_t buffer;
    mp_buffer_info_t buffer_info;

    mp_int_t size = mp_obj_get_int(size_in);
    buffer = mp_obj_new_bytes_of_zeros(size);
    mp_get_buffer_raise(buffer, &buffer_info, MP_BUFFER_READ);
    
    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
    // enable CryptoCell hardware
    NRF_CRYPTOCELL->ENABLE = 1;
    ret = SaSi_LibInit();
    if (ret != 0) return mp_const_none;
    ret = CRYS_RndInit(&rndState, &rndWorkBuff);
    if (ret != 0) return mp_const_none;
    
    ret = CRYS_RND_GenerateVector(&rndState, size, buffer_info.buf);
    if (ret != 0) return mp_const_none;
    
    // disable CryptoCell hardware
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
    NRF_CRYPTOCELL->ENABLE = 0;
    SaSi_LibFini();

    // return random buffer
    return MP_OBJ_TO_PTR(buffer);
}
// Define a Python reference to the function above
STATIC MP_DEFINE_CONST_FUN_OBJ_1(cc310_random_obj, cc310_random);


// Define all properties of the example module.
// Table entries are key/value pairs of the attribute name (a string)
// and the MicroPython object reference.
// All identifiers and strings are written as MP_QSTR_xxx and will be
// optimized to word-sized integers by the build system (interned strings).
STATIC const mp_rom_map_elem_t cc310_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_cc310) },
    { MP_ROM_QSTR(MP_QSTR_sha256), MP_ROM_PTR(&cc310_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_hmac_sha256), MP_ROM_PTR(&cc310_hmac_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_genkeypair), MP_ROM_PTR(&cc310_ec_genkeypair_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_sign), MP_ROM_PTR(&cc310_ec_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_dh), MP_ROM_PTR(&cc310_ec_dh_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_cbc), MP_ROM_PTR(&cc310_aes_cbc_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes256_cbc), MP_ROM_PTR(&cc310_aes256_cbc_obj) },
    { MP_ROM_QSTR(MP_QSTR_random), MP_ROM_PTR(&cc310_random_obj) },
};
STATIC MP_DEFINE_CONST_DICT(cc310_module_globals, cc310_module_globals_table);

// Define module object.
const mp_obj_module_t cc310_user_cmodule = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&cc310_module_globals,
};

// Register the module to make it available in Python
MP_REGISTER_MODULE(MP_QSTR_cc310, cc310_user_cmodule, MODULE_CC310_ENABLED);
