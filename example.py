import os
from time import sleep

from tapo import Bulb, BulbException

bulb = Bulb("192.168.0.100", "svinerus@gmail.com", os.environ['pass'])


def tiktok():
    from itertools import cycle
    for color_hue in cycle([270, 60, 1, 180]):
        try:
            bulb.set_color(color_hue, 100)
            sleep(0.05)

            bulb.set_color(0, 0)
            sleep(0.05)
        except BulbException as ex:
            print(ex)


bulb.power(True)
bulb.set_brightness(100)

tiktok()
