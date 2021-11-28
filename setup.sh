#!/bin/bash

alg=$1
d=$HOME"/Desktop/projects/"
if [ "$2" != "" ]; then
  echo "Custom directory $2 Selected"
  d=$2
fi

if [ "$1" = "-a" -o "$1" = "--aes" ]; then
  echo "AES Selected"
  echo "Adding proper configuratiion files..."
  cp -f AES/aes.c AES/radiolink.c $d"crazyflie-firmware/src/hal/src"
  cp -f AES/aes.h AES/radiolink.h $d"crazyflie-firmware/src/hal/interface"
  cp -f AES/Makefile $d"crazyflie-firmware"
  cp -f AES/radiodriver.py $d"crazyflie-lib-python/cflib/crtp/"
  echo "Done."
elif [ "$1" = "-b" -o "$1" = "--blowfish" ]; then
  echo "Blowfish Selected"
  echo "Adding proper configuration files..."
  cp -f Blowfish/blowfish.c Blowfish/radiolink.c $d"crazyflie-firmware/src/hal/src"
  cp -f Blowfish/blowfish.h Blowfish/radiolink.h $d"crazyflie-firmware/src/hal/interface"
  cp -f Blowfish/Makefile $d"crazyflie-firmware"
  cp -f Blowfish/radiodriver.py $d"crazyflie-lib-python/cflib/crtp/"
  echo "Done."
elif [ "$1" = "-p" -o "$1" = "--present" ]; then
  echo "Present Selected"
  echo "Adding proper configuration files..."
  cp -f Present/present.c Present/radiolink.c Present/Tables_4bit.inc Present/chaskey.c $d"crazyflie-firmware/src/hal/src"
  cp -f Present/present.h Present/radiolink.h $d"crazyflie-firmware/src/hal/interface"
  cp -f Present/Makefile $d"crazyflie-firmware"
  cp -f Present/radiodriver.py Present/present.c Present/libpres.so Present/Tables_4bit.inc Present/chaskey.c Present/libchas.so $d"crazyflie-lib-python/cflib/crtp/"

  # cp -f Present/chaskey.c $d"crazyflie-firmware/src/hal/src"
  # cp -f Present/chaskey.c Present/libchas.so $d"crazyflie-lib-python/cflib/crtp/"
  

  echo "Done."
elif [ "$1" = "-x" -o "$1" = "--xtea" ]; then
  echo "XTEA Selected"
  echo "Adding proper configuration files..."
  cp -f XTEA/xtea.c XTEA/radiolink.c $d"crazyflie-firmware/src/hal/src"
  cp -f XTEA/xtea.h XTEA/radiolink.h $d"crazyflie-firmware/src/hal/interface"
  cp -f XTEA/Makefile $d"crazyflie-firmware"
  cp -f XTEA/radiodriver.py XTEA/xtea.c XTEA/libxtea.so $d"crazyflie-lib-python/cflib/crtp/"
  echo "Done."
else
  echo "Invalid Argument! Valid arguments are => [-a/--aes, -b/--blowfish, -p/--present, -x/--xtea]"
fi
