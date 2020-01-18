#ifndef ENCRYPT_H_INCLUDED                                                  
#define ENCRYPT_H_INCLUDED

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <iostream>
#include <vector>
#include <stdint.h>
#include "utils.h"

class HexType;

class Encrypt
{
    public:
        virtual void CreateCipherText(void) = 0;
        HexType GetCipherText (void);

        HexType XorBlocks(HexType a, HexType b);
        HexType KeyAdd (HexType words_in, HexType key);
        HexType ByteSub (HexType words_in);
        HexType RotateBlock (HexType words_in);
        HexType ShiftRows (HexType words_in);
        HexType MixCol (HexType words_in);

        void Print (void);
    
    protected:
        HexType *plainText;
        HexType *cipherText;		
        std::vector<HexType> keySchedule;
};

class EncryptECB : public Encrypt
{
    public:
        EncryptECB (HexType i, std::vector<HexType> ks);
        EncryptECB (void);
        ~EncryptECB (void);

        HexType EncryptInputECB(HexType i, std::vector<HexType> ks);
        void CreateCipherText(void);
};


class EncryptCBC : public Encrypt
{
    public:
        EncryptCBC (HexType i, std::vector<HexType> ks, HexType iv);
        EncryptCBC (void);

        HexType EncryptInputCBC(HexType i, HexType hiv, std::vector<HexType> ks);
        void CreateCipherText(void);
    private:
        HexType *initVector;
};

#endif
