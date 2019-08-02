# Crazyflie-Custom-Encryption
A set of auxiliary files to allow custom Crazyflie communication with AES, Blowfish, XTEA, &amp; PRESENT encryption 

## Getting Started
This code assumes that you are using the Bitcraze VM for developers. If you are not using the Bitcraze VM you will need the [Crazyflie Client](https://github.com/bitcraze/crazyflie-clients-python), the [Python Library](https://github.com/bitcraze/crazyflie-lib-python), and the [Crazyflie Firmware](https://github.com/bitcraze/crazyflie-firmware)

To integrate one of the encryption algorithms you'll need to run setup.sh

- AES => `./setup.sh -a` or `./setup.sh --aes`
- Blowfish => `./setup.sh -b` or `./setup.sh --blowfish`
- XTEA => `./setup.sh -x` or `./setup.sh --xtea`
- PRESENT => `./setup.sh -p` or `./setup.sh --present` 

If the script isn't being run on the Bitcraze VM, the directory containing the previously mentioned github projects must be entered.

Example: `./setup.sh -a ~/Documents/Crazyflie_Projects/`

## Additional Work for XTEA and PRESENT
### Uploading Code
Before uploading code to the Crazyflie, edit radiodriver.py

In crazyflie-lib-python/cflib/crtp/radiodriver.py comment out `tea = ctypes.CDLL('./libxtea.so')` or `pres = ctypes.CDLL('./libpres.so')`

Uncomment the line from radiodriver.py after the upload is complete.
### Editing code 
If you plan to edit code on the client side, you'll need to compile the c code into `libxtea.so` or `libpres.so` depending on which algorithm you're using.

Once you've made changes to present.c or tea.c run the following command: 
`gcc -shared -o <name>.so -fPIC <name>.c`
