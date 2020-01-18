#include "var-type-functions.h"

char      
GetBase64Char (int b)                                           
{         
    char b64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    b64[64] = '=';

    return (b64[b]);
}       

uint8_t
GetBase64Value (char b)
{
    char b64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for (uint8_t i = 0; i < 64; i++)
    {
        if (b == b64[i])
        {
            return i;
        }
    }

    return 64;
}

char
GetHexChar (int h)
{
    char hex[] = "0123456789abcdef";
    return (hex[h]);
}

uint8_t
GetHexValue (char c)
{
    char hex[17] = "0123456789abcdef";

    for (uint8_t i = 0; i < 16; i++)
    {
        if (tolower(c) == hex[i])
        {
            return i;
        }
    }

    return 16;
}
