def initialize():
    from microcontroller import nvm
    if nvm[:5] == bytes(5):
        from keystore import KS_CTAP2, KS_PIN, KS_U2F, Counter
        for k in [KS_CTAP2(), KS_PIN(), KS_U2F()]:
            k.gen_new_keys()
            k.save_keystore()
        Counter(0).reset()
        Counter(4).reset()


def loop():
    import hid
    from u2f import u2f
    from ctap2 import ctap2
    from ctap_errors import CTAP2_ERR_KEEPALIVE_CANCEL
    from up_check import ButtonLongPressed
    from util import reboot_to_bootloader

    h = hid.hid()
    blp = ButtonLongPressed(4)

    ret = None
    while True:
        if blp.check() is True:
            reboot_to_bootloader()
        ret = h.receive()
        if ret is not None:
            cmd, data = ret
            if cmd in (hid.CTAPHID_MSG, hid.CTAPHID_CBOR):
                if cmd == hid.CTAPHID_MSG:
                    h.send(cmd, u2f(data))
                else:
                    resp = ctap2(data, h)
                    if h.is_cancelled():
                        h.send(cmd, CTAP2_ERR_KEEPALIVE_CANCEL)
                    else:
                        h.send(cmd, resp)


initialize()
try:
    loop()
except:
    while True:
        pass  # needs a power recycle
