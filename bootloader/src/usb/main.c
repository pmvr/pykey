#include <stdio.h>
#include <stdint.h>

#include "rsa_verify.h"


uint8_t char2byte(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
}

void hex2bin(char *hex, uint8_t *bin) {
    while (*hex) {
        *bin = (char2byte(hex[0]) << 4) + char2byte(hex[1]);
        bin += 1;
        hex += 2;
    }
}

int main(int argc, char **argv) {
    uint8_t hash[32];
    uint8_t signature[256];
    
    hex2bin(argv[1], hash);
    hex2bin(argv[2], signature);
    
    return rsa_verify(hash, signature);
}
