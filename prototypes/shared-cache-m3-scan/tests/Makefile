# Host tests for the pure parts of the 3.0b scanner (synthetic fixtures only). Run under the capped wrapper.
CC ?= gcc
CFLAGS ?= -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=undefined
TESTS = test_a64 test_trie test_patch_v4
all: $(TESTS)
test_%: test_%.c check.h enc.h ../a64.h ../trie.h ../patch_v4.h ../patch_v4_check.h
	$(CC) $(CFLAGS) -o $@ $<
test: all
	@for t in $(TESTS); do echo "== $$t"; ./$$t || exit 1; done
clean:
	rm -f $(TESTS)
