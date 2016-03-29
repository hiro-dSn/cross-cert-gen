# ======================================================================
#   cross-cert-gen - Cross-Certificate Generator
#   [ Makefile ]
#   Written by Hiroshi KIHIRA
# ======================================================================


# --------------------------------------------------
#   Compiler and Compiler flags
CC = gcc
LIBS = -lcrypto


# --------------------------------------------------
#   Variables
BIN = cross-cert-gen
SRC = cross-cert-gen.c


# --------------------------------------------------
#   Targets
all: cross-cert-gen

cross-cert-gen: $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LIBS)


# --------------------------------------------------
#   clean
.PHONY: clean
clean: 
	$(RM) -v $(BIN)

# ======================================================================

