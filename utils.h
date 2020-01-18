#ifndef UTILS_H_INCLUDED                           
#define UTILS_H_INCLUDED

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
#include "var-type.h"

//generate rabdom 16 byte key
Words GetRandomKey (void);
Words GetRandomIV (size_t s);

uint8_t ForwardSubBox (int x, int y);
uint8_t InverseSubBox (int x, int y);

uint8_t E_Table (int x, int y);
uint8_t L_Table (int x, int y);

//FileReader class

class HexType;
class AsciiType;
class Base64Type;

class FileReader 
{
    public:
        FileReader (std::string f, bool i);

        HexType GetHex (void);
        AsciiType GetAscii (void);
        Base64Type GetBase64 (void);
    private:
        int GetNumberOfLines (std::string filename);
        char *c; 
        size_t total_length;
};

//KEYTYPE Class

class HexType;

class KeyType
{
    public:
        KeyType (HexType k);
        KeyType (bool CreateRandomKey);
        KeyType (void);

        std::vector<HexType> GetKeySchedule (void);
        void Print(void);

    private:
        void GetKeyWords (HexType tmp, Words **out);
        void CreateKeySchedule (void);
        void NonlinearKeyFunction (Words in, 
                                   Words **out,
                                   int round_number
                                  );

        //vector to store complete key schedule
        std::vector<HexType> keySchedule;    
};

#endif
