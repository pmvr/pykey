from time import sleep
import board
from digitalio import DigitalInOut, Direction


def flash_led():
    led = DigitalInOut(board.LED1)
    led.direction = Direction.OUTPUT
    for i in range(10):
        if i % 2 == 0:
            led.value = True
        else:
            led.value = False
        sleep(0.08)
