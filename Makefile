TARGET = libnpnt
LIBS = -lm
CC = gcc
CFLAGS = -g -Wall
BUILDDIR = build

.PHONY: default all clean

default: $(BUILDDIR)/$(TARGET).so
all: default

OBJECTS = $(patsubst src/%.c, build/%.o, $(wildcard src/*.c))
SRC = $(wildcard src/*.c)
HEADERS = $(wildcard inc/*.h)


$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(OBJECTS): $(SRC) $(HEADERS) $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(BUILDDIR)/$(TARGET) $(OBJECTS)

$(BUILDDIR)/$(TARGET).so: $(OBJECTS) $(BUILDDIR)
	$(CC) $(OBJECTS) -Wall $(LIBS) -shared -o $@

clean:
	rm -r $(BUILDDIR)
