# pykey
This project is an implementation of the [FIDO2](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html) and [U2F](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-bt-protocol-v1.2-ps-20170411.htmlhttps://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-bt-protocol-v1.2-ps-20170411.html) standards on a [NRF52840 Dongle](https://www.nordicsemi.com/?sc_itemid=%7BCDCCA013-FE4C-4655-B20C-1557AB6568C9%7D) (PCA10059) using Adafruit's [CircuitPython](https://circuitpython.org/).

It uses the HID interface for communication.

# Structure
This project consists of 4 parts:
  * A secure booloader based on [Adafruit nRF52 Bootloader](https://github.com/adafruit/Adafruit_nRF52_Bootloader), which only accepts signed UF2 files via USB MSC.
  * [CircuitPython](https://github.com/adafruit/circuitpython) 5, where the usage of the Arm CryptoCell-310 for cryptographic computations has been added to the nrf port as a module.
  * The module for the Arm CryptoCell-310.
  * The implementation of FIDO2 and U2F in Python.

# Security
## Bootloader
The bootloader has been modified such that DFU and OTA is not possible. The only way to upload new firmware is via [UF2](https://github.com/Microsoft/uf2).

UF2 files consits of blocks of 512 bytes, with a payload of 476 bytes of data of the hex file. Since only a maximum of 256 bytes are used, the remaining free bytes are used to transmit a 2048 bit RSA signature of the image. The image is discarded if the signature is invalid.

Part of the bootloader is also the device's ec private key, which is used in the MakeCredential command (FIDO2) and register command (U2F) to sign the response. Note, that the device's attestation certificate `fido2_u2f/cert.der` is issued on the relying public key. Of course, it is important to replace this key and the according certificate, if this project is deployed.

**TODO**: For final release access port protection ([nRF52 APPPROTECT](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.nrf52832.ps.v1.1%2Fdif.html&cp=2_2_0_15_1&anchor=concept_udr_mns_1s)) must be activated.

## Adapted CircuitPython
The nrf port of CircuitPython makes use of the CryptoCell-310. In particular support for SHA256, HMAC-SHA256, ECDSA, ECDH, AES-128 andd secure random numbers has been added.

For the PIN protocol the AES-256 is required, which is not supported by the CryptoCell 310 in hardware. This is why [Tiny AES](https://github.com/kokke/tiny-AES-c) has also been added.

In addition, the implementation of FIDO2/U2F is included to the final hex image. On the first boot of the image, the implementation is copied to the internal FAT filesystem.

The only remaing interface is USB HID with the FIDO report descriptor. This has been configured in `mpconfigboard.mk` for the `PCA10059` and `hid_report_descriptors.py` in the `tools` directory.

## Implementation of FIDO2/U2F
The implementation is done in Python.

 * The security level is 128 bit.
 * The supported public key algorithm is ECDSA with secp256r1 only.
 * The PublicKeyCredentialDescriptors / key handles are encrypted with AES-128-CBC and a random IV. Authenticity is provided by an HMAC-SHA256.
 * For random numbers the true random number generator of the CryptoCell 310 is used, which meets the NIST 800-90B3 and AIS-31 (Class “P2 High”) standards.
 * Resident keys are stored on the internal flash.

# Setup and Building

## Bootloader
The device's private key is stored in `src/secec.c`. Note, a fake value has been commited to this repository.

Change to the directory `bootloader/`, execute

`make BOARD=pca10059 genhex`

then merge the image `pca10059_bootloader-0.3.2-dirty-nosd.hex` with the soft device S140

`hexmerge.py _build-pca10059/pca10059_bootloader-0.3.2-dirty-nosd.hex ./lib/softdevice/s140_nrf52_6.1.1/s140_nrf52_6.1.1_softdevice.hex -o pca10059_bootloader.hex`

`hexmerge` can be found in [IntelHex](https://pypi.org/project/IntelHex/).

In order to put the bootloader onto the NRF52840 Dongle this [OpenOCD guidance](https://www.rototron.info/circuitpython-nrf52840-dongle-openocd-pi-tutorial/) is very helpfull. Otherwise one can use a debugging probe such as Segger J-link.

## Adapted CircuitPython
The [original project](https://github.com/adafruit/circuitpython) gives a general guidance for building CircuitPython. In the `nrf` directory execute

`make BOARD=pca10059 -j17 USER_C_MODULES=../../../modules`

The modules directory contains one module only `cc310` it holds the implementation of the cryptographic libraries.

## FIDO2/U2F Implementation
Optionally, `mpy-cross` can be used to precompile the python source code.

The implementation is included in the image of the adapted CircuitPython. Therefore, in execute

`utils/make_cheader.py *.mpy main.py boot.py cert.der`

which generates a C header file `fido-drive.h`, which as to be copied to `circuitpython/supervisor/shared/`. If CircuitPython boots it copies the implementation to the internal FAT filesystem. Then, as usual `boot.py` and then `main.py` is executed.

For debugging and developing it is helpfull to use the REPL console. Therefore, the USB CDC must be activated in `mpconfigboard.mk`.

# Conformance
PyKey passed FIDO Conformance Tools tests for FIDO2 and U2F:

![](https://github.com/pmvr/pykey/blob/master/FIDO2-Conformance-Tools-Passed.png)

![](https://github.com/pmvr/pykey/blob/master/U2F-Conformance-Tools-Passed.png)


# License

[MIT](https://opensource.org/licenses/MIT)
