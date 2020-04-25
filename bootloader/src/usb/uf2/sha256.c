#include "nrf_cc310/crys_hash.h"
#include "boards.h"

#include <string.h>


#define NRF_CRYPTOCELL_BASE 0x5002A000UL
#define NRF_CRYPTOCELL ((NRF_CRYPTOCELL_Type*) NRF_CRYPTOCELL_BASE)

typedef enum {
        SA_SILIB_RET_OK = 0, /*!< Success defintion.*/
        SA_SILIB_RET_EINVAL_CTX_PTR, /*!< Illegal context pointer.*/
        SA_SILIB_RET_EINVAL_WORK_BUF_PTR, /*!< Illegal work buffer pointer.*/
        SA_SILIB_RET_HAL, /*!< Error returned from HAL layer.*/
        SA_SILIB_RET_PAL, /*!< Error returned from PAL layer.*/
        SA_SILIB_RET_EINVAL_HW_VERSION,    /*!< Invalid HW version. */
        SA_SILIB_RET_EINVAL_HW_SIGNATURE,  /*!< Invalid HW signature. */
        SA_SILIB_RESERVE32B = 0x7FFFFFFFL  /*!< Reserved.*/
} SA_SilibRetCode_t;
SA_SilibRetCode_t SaSi_LibInit(void);
void SaSi_LibFini(void);


void cc310_sha256(uint8_t *buffer, size_t len, uint8_t *hash) {
    CRYS_HASH_Result_t hashOutBuff;

    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
    // enable CryptoCell hardware
    NRF_CRYPTOCELL->ENABLE = 1;
    SaSi_LibInit();
    CRYS_HASH(CRYS_HASH_SHA256_mode, buffer, len, hashOutBuff);
    // disable CryptoCell hardware
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
    NRF_CRYPTOCELL->ENABLE = 0;
    SaSi_LibFini();
    // return 32-Byte hash value
    memcpy(hash, (uint8_t*)hashOutBuff, 32);
}
