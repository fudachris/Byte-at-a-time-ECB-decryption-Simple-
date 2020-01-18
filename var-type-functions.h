#ifndef VARFUN_H_INCLUDED                           
#define VARFUN_H_INCLUDED

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>

struct Words
{
    uint8_t *w;
    size_t l;
};

char GetBase64Char (int b);
uint8_t GetBase64Value (char b);

char GetHexChar (int h);
uint8_t GetHexValue (char c);

#endif
