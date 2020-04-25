from micropython import const
from time import sleep, monotonic
from board import LED1, SW1
from digitalio import DigitalInOut, Direction
from ctap_errors import CTAP2_OK, CTAP2_ERR_ACTION_TIMEOUT, CTAP2_ERR_KEEPALIVE_CANCEL

DELAY_TIME = const(10)   # 10 ms
WINK_FREQ = const(10)  # Hz


def up_check(channel, led_type=LED1):
    led = DigitalInOut(led_type)
    led.direction = Direction.OUTPUT
    button = DigitalInOut(SW1)
    button.direction = Direction.INPUT
    MAX_TIME = const(10000)  # 10 seconds
    counter = 0
    ka_counter = 0
    while True:
        if button.value is False:
            led.deinit()
            button.deinit()
            return CTAP2_OK
        if counter >= MAX_TIME:
            led.deinit()
            button.deinit()
            return CTAP2_ERR_ACTION_TIMEOUT
        if ((counter * WINK_FREQ) // 2000) % 2 == 0:
            led.value = False
        else:
            led.value = True
        sleep(DELAY_TIME / 1000)
        counter += DELAY_TIME
        ka_counter += DELAY_TIME
        if ka_counter > 70:
            if channel is not None:
                if channel.is_cancelled():
                    led.deinit()
                    button.deinit()
                    return CTAP2_ERR_KEEPALIVE_CANCEL
                channel.keepalive(channel.STATUS_UPNEEDED)
            ka_counter = 0


def u2f_up_check(led_type=LED1):
    led = DigitalInOut(led_type)
    led.direction = Direction.OUTPUT
    button = DigitalInOut(SW1)
    button.direction = Direction.INPUT
    MAX_U2F_TIME = const(50)  # 50 ms
    counter = 0
    led.value = False
    while True:
        if button.value is False:
            led.value = True
            led.deinit()
            button.deinit()
            return CTAP2_OK
        if counter >= MAX_U2F_TIME:
            led.value = True
            led.deinit()
            button.deinit()
            return CTAP2_ERR_ACTION_TIMEOUT
        sleep(DELAY_TIME / 1000)
        counter += DELAY_TIME


class ButtonLongPressed:
    def __init__(self, period):
        self.period = period
        self.last_button_pressed = monotonic() - 10.0
        self.button_pressed_duration = 0.0

    def check(self):
        button = DigitalInOut(SW1)
        button.direction = Direction.INPUT
        if button.value is True:
            # no button button pressed
            button.deinit()
            return False
        else:
            button.deinit()
            t = monotonic()
            if t - self.last_button_pressed < 0.05:
                self.button_pressed_duration += t - self.last_button_pressed
            self.last_button_pressed = t
            if self.button_pressed_duration > self.period:
                self.button_pressed_duration = 0.0
                return True
