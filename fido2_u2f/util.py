def der_encode_signature(r, s):
    # sig = 30 len(r)+len(s)+4 02 len(r) r 02 len(s) s
    while r[0] == 0:
        r = r[1:]
    if r[0] & 0x80 != 0:
        r = b'\x00' + r
    while s[0] == 0:
        s = s[1:]
    if s[0] & 0x80 != 0:
        s = b'\x00' + s
    return bytes((0x30,
                  len(r) + len(s) + 4, 0x02,
                  len(r))) + r + bytes((0x02, len(s))) + s


def reboot_to_bootloader():
    import microcontroller
    microcontroller.on_next_reset(microcontroller.RunMode.BOOTLOADER)
    microcontroller.reset()
