all:
	/home/system/Android/Sdk/ndk/29.0.13599879/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang android-shared.c -shared -lm -llog -g -O0
	adb push a.out /data/local/tmp/shared.so

cpp:
	/home/system/Android/Sdk/ndk/29.0.13599879/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang++ android-cpp-shared.cpp -shared -g -O0
	adb push a.out /data/local/tmp/shared.so

linux:
	clang linux-shared.c -lelf -shared -g -O0