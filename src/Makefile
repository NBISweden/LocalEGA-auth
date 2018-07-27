#
# Makefile for the NSS and PAM modules used in Local EGA
#
# Blowfish code from http://www.openwall.com/crypt/
#

NSS_LD_SONAME=-Wl,-soname,libnss_ega.so.2
NSS_LIBRARY=libnss_ega.so.2.0
PAM_LIBRARY = pam_ega.so
KEYS_EXEC = ega_ssh_keys

CC=gcc
LD=ld
AS=gcc -c
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -I. -I/usr/local/include -O2 -DPROGRESS
LIBS=-lpam -lcurl -ljq -L/usr/local/lib -lsqlite3

EGA_LIBDIR=/usr/local/lib/ega
EGA_BINDIR=/usr/local/bin

HEADERS = utils.h config.h backend.h cega.h homedir.h $(wildcard blowfish/*.h)

NSS_SOURCES = nss.c config.c backend.c cega.c homedir.c
NSS_OBJECTS = $(NSS_SOURCES:%.c=%.o)

PAM_SOURCES = pam.c config.c backend.c cega.c homedir.c $(wildcard blowfish/*.c)
PAM_OBJECTS = $(PAM_SOURCES:%.c=%.o) blowfish/x86.o

KEYS_SOURCES = keys.c config.c backend.c cega.c
KEYS_OBJECTS = $(KEYS_SOURCES:%.c=%.o)

.PHONY: all debug clean install install-nss install-pam
.SUFFIXES: .c .o .S .so .so.2 .so.2.0

all: install

debug1: CFLAGS += -DDEBUG=1 -g
debug1: install

debug2: CFLAGS += -DDEBUG=2 -g
debug2: install

debug3: CFLAGS += -DDEBUG=3 -g
debug3: install

$(NSS_LIBRARY): $(HEADERS) $(NSS_OBJECTS)
	@echo "Linking objects into $@"
	@$(CC) -shared $(NSS_LD_SONAME) -o $@ $(LIBS) $(NSS_OBJECTS)

$(PAM_LIBRARY): $(HEADERS) $(PAM_OBJECTS)
	@echo "Linking objects into $@"
	@$(LD) -x --shared -o $@ $(LIBS) $(PAM_OBJECTS)

$(KEYS_EXEC): $(HEADERS) $(KEYS_OBJECTS) 
	@echo "Creating $@"
	@$(CC) -o $@ $(KEYS_OBJECTS) $(LIBS)

blowfish/x86.o: blowfish/x86.S $(HEADERS)
	@echo "Compiling $<"
	@$(AS) -o $@ $<

%.o: %.c $(HEADERS)
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

install-nss: $(NSS_LIBRARY)
	@[ -d $(EGA_LIBDIR) ] || { echo "Creating lib dir: $(EGA_LIBDIR)"; install -d $(EGA_LIBDIR); }
	@echo "Installing $< into $(EGA_LIBDIR)"
	@install $< $(EGA_LIBDIR)

install-pam: $(PAM_LIBRARY)
	@[ -d $(EGA_LIBDIR) ] || { echo "Creating lib dir: $(EGA_LIBDIR)"; install -d $(EGA_LIBDIR); }
	@echo "Installing $< into $(EGA_LIBDIR)"
	@install $< $(EGA_LIBDIR)

install-keys: $(KEYS_EXEC)
	@[ -d $(EGA_BINDIR) ] || { echo "Creating bin dir: $(EGA_BINDIR)"; install -d $(EGA_BINDIR); }
	@echo "Installing $< into $(EGA_BINDIR)"
	@install -m 700 $< $(EGA_BINDIR)

install: install-nss install-pam install-keys
	@echo "Do not forget to run ldconfig and create/configure the file /etc/ega/auth.conf"
	@echo "Look at the auth.conf.sample here, for example"


clean:
	-rm -f $(NSS_LIBRARY) $(NSS_OBJECTS)
	-rm -f $(PAM_LIBRARY) $(PAM_OBJECTS)
	-rm -f $(KEYS_EXEC) $(KEYS_OBJECTS)
