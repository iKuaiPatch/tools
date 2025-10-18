CC = gcc

CFLAGS = -Wall -Wextra -O3 -std=c99

rootfs: md5.c rootfs.c
	@$(CC) $(CFLAGS) -o rootfs md5.c rootfs.c

clean:
	@$(RM) rootfs
