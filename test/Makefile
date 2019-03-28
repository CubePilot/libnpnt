TARGET = test_ifaces
LIBS = -lm
CC = gcc
CFLAGS = -g -Wall -I../ -I. -I../inc
ifeq ($(MAKECMDGOALS),wolfssl)
CFLAGS += -I/usr/local/Cellar/wolfssl/4.0.0/include/ -I/usr/local/opt/openssl/include -DRFM_USE_WOLFSSL
LDFLAGS = -L/usr/local/Cellar/wolfssl/4.0.0/lib -lwolfssl -lnetwork -L/usr/local/opt/openssl/lib -lssl -lcrypto
else
CFLAGS += -I/usr/local/opt/openssl/include -DRFL_USE_LIBOPENSSL
LDFLAGS = -L/usr/local/opt/openssl/lib -lssl -lcrypto
endif
BUILDDIR = build

.PHONY: default openssl wolfssl clean

openssl: $(BUILDDIR)/$(TARGET)
wolfssl: $(BUILDDIR)/$(TARGET)


SRC := test_ifaces.c \
       ../jsmn/jsmn.c \
       ../src/npnt_helpers.c \
       ../src/base64.c \
       ../src/art_proc.c \
       ../mxml/mxml-attr.c \
       ../mxml/mxml-entity.c \
       ../mxml/mxml-file.c \
       ../mxml/mxml-get.c \
       ../mxml/mxml-index.c \
       ../mxml/mxml-node.c \
       ../mxml/mxml-private.c \
       ../mxml/mxml-search.c \
       ../mxml/mxml-set.c \
       ../mxml/mxml-string.c

VPATH  := $(sort $(dir $(SRC)))

HEADERS = $(wildcard ../inc/*.h)
OBJECTS = $(addprefix $(BUILDDIR)/, $(notdir $(SRC:.c=.o)))

$(OBJECTS): | $(BUILDDIR)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(OBJECTS): $(BUILDDIR)/%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(BUILDDIR)/$(TARGET) $(OBJECTS)

$(BUILDDIR)/$(TARGET): $(OBJECTS) $(BUILDDIR)
	$(CC) $(OBJECTS) -g -Wall $(LDFLAGS) $(LIBS) -o $@

clean:
	rm -r $(BUILDDIR)
