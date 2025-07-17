CC = gcc

CFLAGS = -Wall `pkg-config fuse3 --cflags`
LDFLAGS = `pkg-config fuse3 --libs` -lssl -lcrypto

SRCDIR = src
OBJ = $(SRCDIR)/fuse_core.o $(SRCDIR)/fuse_main.o  # Add your object files here
TARGET = fuse_fs

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(SRCDIR)/*.o $(TARGET)

