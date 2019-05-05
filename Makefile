TARGET = libnpnt.a
CC ?= gcc
AR ?= ar
CFLAGS = -g -Wall -I. -Iinc/
ifeq ($(MAKECMDGOALS),wolfssl)
CFLAGS += -DRFM_USE_WOLFSSL
else
CFLAGS += -DRFL_USE_LIBOPENSSL
endif
BUILDDIR = build

.PHONY: default openssl wolfssl clean

openssl: $(BUILDDIR)/$(TARGET)
wolfssl: $(BUILDDIR)/$(TARGET)


SRC := jsmn/jsmn.c \
       src/base64.c \
       src/art_proc.c \
       src/control.c \
       mxml/mxml-attr.c \
       mxml/mxml-entity.c \
       mxml/mxml-file.c \
       mxml/mxml-get.c \
       mxml/mxml-index.c \
       mxml/mxml-node.c \
       mxml/mxml-private.c \
       mxml/mxml-search.c \
       mxml/mxml-set.c \
       mxml/mxml-string.c

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
	$(AR) rcs $@ $(OBJECTS)

clean:
	rm -r $(BUILDDIR)
