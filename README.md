# twamp-dissector

A Two-Way Active Measurement Protocol (TWAMP) dissector for Wireshark (1.12.X and above).
 
Written by Murat Demirten

## Features

* Unauthenticated twamp control sessions fully supported

* Twamp UDP test session ports extracted from control handshake process 

## Build Instructions (Debian - Jessie)

1. Install the `wireshark-dev`, `libglib2.0-dev` and `cmake`:

```
$ sudo apt-get install wireshark-dev libglib2.0-dev cmake
```

2. Create `build` dir in main directory and run `cmake` within as below:

```
$ mkdir build && cd build
$ cmake -DWIRESHARK_INCLUDE_DIRS=/usr/include/wireshark ..
```

3. If everything goes well, you can use `make` and `make install` within build directory:

```
$ make
$ make install
```

Install target will copy `twamp.so` automatically in your `~/.wireshark/plugins` folder.

## TODO

* Authenticated and encrypted sessions will be supported in future
