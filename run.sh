#!/bin/sh

reset; /opt/cross/bin/aarch64-linux-g++ -static -std=c++14 -o prog AndroFace.cpp && adb push prog /data/local/tmp/prog && adb shell ./data/local/tmp/prog find untrusted_app
