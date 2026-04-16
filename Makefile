CC = clang
CFLAGS = -Wall -Wextra -O2
TARGET = macbridge

$(TARGET): macbridge.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: clean
