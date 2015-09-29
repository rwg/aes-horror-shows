.PHONY: all clean pb-loader pb-program

TARGETS = aes128-encrypt aes128-encrypt.hex aes128-encrypt.lst

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

aes128-encrypt: aes128-encrypt.s
	msp430-gcc -mmcu=msp430f5212 -mcpu=430 -mmpy=none -mdisable-watchdog -g -o aes128-encrypt aes128-encrypt.s

aes128-encrypt.hex: aes128-encrypt
	msp430-objdump -s -j .text -j .rodata aes128-encrypt | perl -ne '($$_)=/^ *[0-9a-f]+((?: (?:[0-9a-f ]{8})){4})  / or next; s/\s//g; print "$$_\n";' > aes128-encrypt.hex

aes128-encrypt.lst: aes128-encrypt
	(msp430-objdump -S -d --insn-width=6 -j .text aes128-encrypt; msp430-objdump -s -t -j .rodata aes128-encrypt) > aes128-encrypt.lst

pb-loader: loader.txt
	pbcopy < loader.txt

pb-program: aes128-encrypt.hex
	pbcopy < aes128-encrypt.hex
