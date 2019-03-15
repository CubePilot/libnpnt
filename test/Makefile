TARGET = test_ifaces
LIBS = -lm -lssl -lcrypto
CC = gcc
CFLAGS = -g -Wall -I../ -I. -I../inc
BUILDDIR = build

.PHONY: default all clean

default: $(BUILDDIR)/$(TARGET)
all: default

SRC := test_ifaces.c \
       npnt_helpers.c \
	   ../jsmn/jsmn.c \
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
	$(CC) $(CFLAGS) -g -c $< -o $@

.PRECIOUS: $(BUILDDIR)/$(TARGET) $(OBJECTS)

$(BUILDDIR)/$(TARGET): $(OBJECTS) $(BUILDDIR)
	$(CC) $(OBJECTS) -g -Wall $(LIBS) -o $@

clean:
	rm -r $(BUILDDIR)
