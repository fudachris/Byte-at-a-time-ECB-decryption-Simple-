#ifndef VARTYPE_H_INCLUDED                           
#define VARTYPE_H_INCLUDED

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <algorithm>
#include "var-type-functions.h"

//ASCIITYPE Class

class HexType;
class Base64Type;

class AsciiType
{        
    public:    
        AsciiType (char *ascii, size_t l);
        AsciiType (Words ascii);
        AsciiType (void);

        Words GetAsciiWords (void);
        HexType GetHex (void);
        Base64Type GetBase64 (void);

        void Print (void);
    private:

        //ascii input
        Words ascii;
        HexType *hex;
        Base64Type *b64;
};    

//BASE64TYPE Class

class AsciiType;
class HexType;
//converts to hex
//converts to ascii
class Base64Type
{
    public:
        Base64Type (char *b64, size_t l);
        Base64Type (uint8_t *b64, size_t l);
        Base64Type (Words b);
        Base64Type (void);

        Words GetBase64Words (void);
        HexType GetHex (void);
        AsciiType GetAscii (void);

        void Print(void);
    private: 
        //b64 input    
        Words b64;
        HexType *hex;
        AsciiType *ascii;
};

//HEXTYPE Class

class AsciiType;
class Base64Type;
//converts to ascii
//converts to base64
class HexType
{
    public:    
        HexType (char *hex, size_t l);
        HexType (uint8_t *hex, size_t l);
        HexType (Words h);
        HexType (void);

        Words GetHexWords (void);
        AsciiType GetAscii (void);
        Base64Type GetBase64 (void);

        void Print (void);

        void InsertStringPad (HexType s);

        //inserts random 5-10 bytes at head/tail
        void InsertRandomPad (void);

        //pads input to bs
        void PadToBlocksize (size_t bs);

        std::string SerializeString (void);
        std::string SerializeString (int a, int b);
        int isECB();
    private:
        size_t GetPadLength (size_t block_size, size_t input_length);
        void PadHead (int pad_l);
        void PadTail (int pad_l);
        //hex input
        Words hex;
        AsciiType *ascii;
        Base64Type *b64;
};

#endif
