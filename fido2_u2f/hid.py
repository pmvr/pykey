from micropython import const
from time import sleep, monotonic
import usb_hid
from os import urandom
from up_check import up_check

SUCCESS = 0
ERR_INVALID_CMD = const(0x01)      # The command in the request is invalid
ERR_INVALID_PAR = const(0x02)      # The parameter(s) in the request is invalid
ERR_INVALID_LEN = const(0x03)      # The length field (BCNT) is invalid for the request
ERR_INVALID_SEQ = const(0x04)      # The sequence does not match expected value
ERR_MSG_TIMEOUT = const(0x05)      # The message has timed out
ERR_CHANNEL_BUSY = const(0x06)     # The device is busy for the requesting channel
ERR_LOCK_REQUIRED = const(0x0A)    # Command requires channel lock
ERR_INVALID_CHANNEL = const(0x0B)  # CID is not valid.
ERR_OTHER = const(0x7F)            # Unspecified error

CTAPHID_ERROR = const(0x3F)        # This command code is used in response messages only
CTAPHID_INIT = const(0x06)
CTAPHID_MSG = const(0x03)
CTAPHID_WINK = const(0x08)
CTAPHID_CBOR = const(0x10)
CTAPHID_CANCEL = const(0x11)
CTAPHID_PING = const(0x01)
CTAPHID_KEEPALIVE = const(0x3B)

PROTOCOL_VER = const(2)
MAJOR_DEV_VER = const(0)
MINOR_DEV_VER = const(1)
BUILD_DEV_VER = const(1)
CAPABILITIES = const(0x05)  # CAPABILITY_CBOR + CAPABILITY_WINK

FIDO_USAGE_PAGE = 0xf1d0
FIDO_USAGE = 1


class hid():
    STATUS_PROCESSING = b'\x01'
    STATUS_UPNEEDED = b'\x02'
    PacketSize = const(64)

    def __init__(self):
        self.h = None
        for device in usb_hid.devices:
            if device.usage_page == FIDO_USAGE_PAGE and \
                    device.usage == FIDO_USAGE:
                self.h = device
                break
        if self.h is None:
            raise ValueError("Could not find matching HID device.")
        self.CID = b'\xff\xff\xff\xff'

    def receive(self, timeout=-1):
        sequence_counter = -1
        data = None
        start_timer = monotonic()
        while True:
            while True:
                req = self.h.read_report(timeout)
                if len(req) == 0:
                    if data is None:
                        return
                    elif monotonic() - start_timer > 4.0:
                        # 8.2.5.2. Transaction timeout
                        return
                    continue
                start_timer = monotonic()
                #print("rec:", req)
                if len(req) > 0:
                    break
            if len(req) != hid.PacketSize:
                self.send_error(ERR_OTHER)
                sequence_counter = -1
                continue
            if req[:7] == b'\xff\xff\xff\xff\x86\x00\x08':
                # cmd == CTAPHID_INIT:
                self.hid_init(req[7:7 + 8])
                sequence_counter = -1
                continue
            if req[:7] == self.CID + b'\x86\x00\x08':
                # cmd == CTAPHID_INIT, abort
                self.hid_init_abort(req[7:7 + 8])
                sequence_counter = -1
                continue
            if req[:4] != self.CID:
                if self.CID == b'\xff\xff\xff\xff':
                    continue
                if sequence_counter == -1 and req[4] & 0x80 == 0:
                    continue
                self.send_error(ERR_INVALID_CHANNEL)
                sequence_counter = -1
                continue
            if sequence_counter == -1:
                if req[4] & 0x80 == 0:
                    self.send_error(ERR_INVALID_CMD)
                    continue
                bcnt = req[5] * 256 + req[6]
                if bcnt > 7609:
                    self.send_error(ERR_INVALID_LEN)
                    continue
                cmd = req[4] & 0x7f
                data = req[7:7 + bcnt]
            else:
                if req[4] != sequence_counter or sequence_counter == 128:
                    self.send_error(ERR_INVALID_SEQ)
                    sequence_counter = -1
                    continue
                data += req[5:5 + bcnt - len(data)]
            if len(data) < bcnt:
                sequence_counter += 1
                continue
            else:
                if cmd == CTAPHID_PING:
                    self.ping(data)
                    sequence_counter = -1
                    continue
                elif cmd == CTAPHID_WINK:
                    if len(data) > 0:
                        self.send_error(ERR_INVALID_LEN)
                    else:
                        self.wink()
                    sequence_counter = -1
                    continue
                elif cmd in (CTAPHID_MSG, CTAPHID_CBOR, CTAPHID_CANCEL):
                    break
                else:
                    self.send_error(ERR_INVALID_CMD)
                    sequence_counter = -1
                    continue

        return cmd, data

    def send(self, cmd, data):
        L = len(data)
        response = self.CID + bytes((cmd | 0x80, L >> 8, L & 0xff)) + data
        #print('resp:', response)
        sequence_counter = 0
        while True:
            if len(response) < hid.PacketSize:
                response += bytes(hid.PacketSize - len(response))
            self.h.send_report(response[:hid.PacketSize])
            if len(response) > hid.PacketSize:
                sleep(0.01)
                response = self.CID \
                    + sequence_counter.to_bytes(1, 'big') \
                    + response[hid.PacketSize:]
                sequence_counter += 1
            else:
                break

    def send_error(self, error):
        self.send(CTAPHID_ERROR, error.to_bytes(1, 'big'))

    def hid_init(self, data):
        if len(data) != 8:
            self.send_error(ERR_INVALID_SEQ)
        else:
            while (True):
                CID = urandom(4)
                if CID != b'\xff\xff\xff\xff' and CID != b'\x00\x00\x00\x00':
                    break
            self.CID = b'\xff\xff\xff\xff'
            self.send(CTAPHID_INIT,
                      data + CID + bytes((PROTOCOL_VER, MAJOR_DEV_VER,
                                          ERR_INVALID_PAR, BUILD_DEV_VER,
                                          CAPABILITIES)))
            self.CID = CID

    def hid_init_abort(self, data):
        if len(data) != 8:
            self.send_error(ERR_INVALID_SEQ)
        self.send(CTAPHID_INIT,
                  data + self.CID + bytes((PROTOCOL_VER, MAJOR_DEV_VER,
                                           ERR_INVALID_PAR, BUILD_DEV_VER,
                                           CAPABILITIES)))

    def ping(self, data):
        self.send(CTAPHID_PING, data)

    def wink(self):
        up_check(self)
        self.send(CTAPHID_WINK, b'')

    def keepalive(self, status):
        self.send(CTAPHID_KEEPALIVE, status)

    def is_cancelled(self):
        ret = self.receive()
        if ret is not None:
            cmd_cancel, _ = ret
            return cmd_cancel == CTAPHID_CANCEL
        return False
