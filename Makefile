CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -pedantic -O2 -Iinclude
LDFLAGS ?=
LIBS    := -lcrypto -lncurses -lz -ldl -lpthread -lm

PREFIX  ?= /usr
BINDIR  := $(PREFIX)/bin

SRC := src/main.c src/common.c src/log.c src/config.c \
       modules/codec.c modules/encode.c modules/decode.c \
       modules/entropy.c modules/inspect.c modules/analyze.c \
       modules/benchmark.c modules/visualize.c modules/report.c \
       modules/plugin.c

OBJ := $(SRC:.c=.o)
BIN := srl

.PHONY: all clean install uninstall test plugins

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# --- tests -----------------------------------------------------------------
test: tests/test_codec
	./tests/test_codec

tests/test_codec: tests/test_codec.c modules/codec.c src/common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# --- example plugin --------------------------------------------------------
plugins: plugins/hello.so

plugins/hello.so: plugins/example_plugin.c
	$(CC) -std=c11 -Wall -Wextra -fPIC -shared -Iinclude $< -o $@

# --- install ---------------------------------------------------------------
install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	@echo "installed to $(DESTDIR)$(BINDIR)/$(BIN)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -f $(OBJ) $(BIN) tests/test_codec plugins/*.so
