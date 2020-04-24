# pykey

This project is an implementation of the [FID02](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html) and [U2F](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-bt-protocol-v1.2-ps-20170411.htmlhttps://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-bt-protocol-v1.2-ps-20170411.html) standards on a [NRF52840 Dongle](https://www.nordicsemi.com/?sc_itemid=%7BCDCCA013-FE4C-4655-B20C-1557AB6568C9%7D) (PCA10059) using Adafruit's [CircuitPython](https://circuitpython.org/).

It uses the HID interface for communication.


# Security

This projects consists of 3 parts:
  * A secure booloader based on [Adafruit nRF52 Bootloader](https://github.com/adafruit/Adafruit_nRF52_Bootloader), which only accepts signed UF2 files via USB MSC.
  * [CircuitPython](https://github.com/adafruit/circuitpython) 5, where the usage of the Arm CryptoCell-310 for cryptographic computations has been added to the nrf port as a module.
  * The implementation of FIDO2 and U2F in Python.

# License

[MIT](https://opensource.org/licenses/MIT)
Python based implementaton of FIDO2 and U2F on a NRF52840 Dongle (PCA10059)
