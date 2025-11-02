all:
	$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang -Iinclude src/*.c -o csoloader -Wno-int-conversion -g -O0 -D_FORTIFY_SOURCE=2 -fstack-protector-strong 
	adb push csoloader /data/local/tmp/csoloader

linux:
	$(CC) -D_GNU_SOURCE -Iinclude src/*.c -o csoloader -Wno-int-conversion -g -O0 -lunwind
