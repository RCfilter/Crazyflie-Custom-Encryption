import array
import binascii
import collections
import logging
import re
import struct
import sys
import threading
import ctypes
import os

# import cflib.drivers.crazyradio as crazyradio
# from .crtpstack import CRTPPacket
# from .exceptions import WrongUriType
# from cflib.crtp.crtpdriver import CRTPDriver
# from cflib.drivers.crazyradio import Crazyradio


# given input key and packet data
k = bytes("chaskey is a mac", 'utf-8')           # Ty ptk may be in the form of a string
t = bytes("test message 1", 'utf-8')         # Message

# translate the data to 


# hardcoded key for now
ptk_py = [int('833D3433', 16), int('009F389F', 16), int('2398E64F', 16), int('417ACF39', 16)]
ptk = (ctypes.c_uint32*4)(*ptk_py) # initialize the array from other Python object (key_px list)

# Find the Chaskey authentication library and load it
home = os.getenv("HOME")
chas = ctypes.CDLL(home +'/projects/crazyflie-lib-python/cflib/crtp/libchas.so')

print(t)

for item in t:
    print(hex(item))

# Initialize fixed size parameter arrays using ctypes
key = (ctypes.c_uint8 * 48)(*[int(0) for x in range(48)])
tag = (ctypes.c_uint8 * 16)(*[int(0) for x in range(16)])
msg = (ctypes.c_uint8 * len(t))(*[t[x] for x in range(len(t))])
len = (ctypes.c_uint)(16)
#len = (ctypes.c_uint32)(*len_py)

print("Message data (m - 512 bits):")
msg_str = ''.join([str(f"{item:X}") for item in msg])
print(msg_str)

print("Set Chaskey Key (K1 - 384 bits):")
chas.chaskey_setkey(key, ptk)
key_str = '0x' + ''.join([str(f"{item:X}") for item in key])
print(key_str)

print("Output Tag (T - 128 bits):")
chas.chaskey_mac(tag, msg, len, key)
tag_str = '0x' + ''.join([str(f"{item:X}") for item in tag])
print(tag_str)
