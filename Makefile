all:
	/home/system/Android/Sdk/ndk/29.0.13599879/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang -Iinclude src/*.c -o csoloader -Wno-int-conversion -g -O0
	adb push csoloader /data/local/tmp/csoloader

linux:
	clang -D_GNU_SOURCE -Iinclude src/*.c -o csoloader -Wno-int-conversion -g -O0