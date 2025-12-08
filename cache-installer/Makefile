ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := y2jb_cache_installer.elf
CFLAGS := -Wall -Werror -g -Iinclude -Llib -lpsl -lSceUserService -lz -lcurl -lminizip -lwolfssl -lzstd

all: $(ELF)

$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)
