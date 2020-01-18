#include "encrypt.h"


//words_in and key variables are 16 bytes each or 32 hex
HexType 
Encrypt::KeyAdd (HexType words_in, HexType key)
{
    //null terminator
    size_t outLength = 32;

    Words out;
    out.w = (uint8_t *)malloc (outLength * sizeof (uint8_t));
    out.l = outLength;

    Words in = (words_in.GetHexWords());
    Words k = (key.GetHexWords());

    for (int i = 0; i < 32; i++)
    {
        uint8_t a = in.w[i];
        uint8_t b = k.w[i];
        uint8_t c = a ^ b;
        out.w[i] =  c;
    }

    HexType rt = HexType(out);

    return rt;
}

//words_in must be 16 bytes or 32 hex
HexType
Encrypt::ByteSub (HexType words_in)
{
    Words in = words_in.GetHexWords();
    size_t len = in.l;

    Words out;
    out.w = (uint8_t *) malloc ((len+1) * sizeof(uint8_t));
    out.l = len;
    out.w[len] = '\0';

    for (size_t i = 0; i < len; i+=2)
    {
        uint8_t x = in.w[i];
        uint8_t y = in.w[i+1];

        uint8_t sub = ForwardSubBox(x,y);

        out.w[i] = (sub & 0xF0) >> 4;
        out.w[i+1] = sub & 0x0F;
    }

    HexType rt = HexType(out);

    return rt;
}

HexType 
Encrypt::RotateBlock (HexType words_in)
{
    Words in = words_in.GetHexWords();
    size_t len = in.l;

    Words out;
    out.w = (uint8_t *) malloc (len * sizeof (uint8_t));
    out.l = len;

    for (int j = 0, i = 0; j < 8; j+=2)
    {
        for (int k =0; k < 32; i+=2, k+=8)
        {
            out.w[i] = in.w[k+j];
            out.w[i+1] = in.w[k+j+1];
        }
    }

    return out;
}

HexType
Encrypt::ShiftRows (HexType words_in)
{
    Words out;

    Words in = words_in.GetHexWords();
    size_t len = in.l;

    out.w = (uint8_t *)malloc (len * sizeof(uint8_t));
    out.l = len;

    out.w[0]=in.w[0];
    out.w[1]=in.w[1];
    out.w[2]=in.w[2];
    out.w[3]=in.w[3];
    out.w[4]=in.w[4];
    out.w[5]=in.w[5];
    out.w[6]=in.w[6];
    out.w[7]=in.w[7];

    out.w[8]=in.w[10];
    out.w[9]=in.w[11];
    out.w[10]=in.w[12];
    out.w[11]=in.w[13];
    out.w[12]=in.w[14];
    out.w[13]=in.w[15];
    out.w[14]=in.w[8];
    out.w[15]=in.w[9];

    out.w[16]=in.w[20];
    out.w[17]=in.w[21];
    out.w[18]=in.w[22];
    out.w[19]=in.w[23];
    out.w[20]=in.w[16];
    out.w[21]=in.w[17];
    out.w[22]=in.w[18];
    out.w[23]=in.w[19];

    out.w[24]=in.w[30];
    out.w[25]=in.w[31];
    out.w[26]=in.w[24];
    out.w[27]=in.w[25];
    out.w[28]=in.w[26];
    out.w[29]=in.w[27];
    out.w[30]=in.w[28];
    out.w[31]=in.w[29];

    return out;
}

int rc1 = 0;

HexType
Encrypt::MixCol(HexType words_in)
{
    uint8_t forwardMatrix[4][4] = 
    {
        {0x02, 0x03, 0x01, 0x01}, 
        {0x01, 0x02, 0x03, 0x01}, 
        {0x01, 0x01, 0x02, 0x03}, 
        {0x03, 0x01, 0x01, 0x02}
    };

    uint8_t *c = (uint8_t *) malloc (32 * sizeof (uint8_t));

    Words in = words_in.GetHexWords();

    uint8_t tmp[4];

    for (int vc = 0, j = 0, wj = 0, fm = 0; vc <32 ; wj += 8, fm++)
    {
        for (int i = 0; i < 8; i+=2, vc += 2)
        {
            int t = 0;
            j = wj;

            for (int k = 0; k < 32; k+=8, t++, j+=2)
            {
                uint8_t x = (in.w[k+i]);
                uint8_t y = (in.w[k+i+1]);

                uint8_t l = L_Table(x,y);

                uint8_t x1 = (forwardMatrix[fm][t] & 0xF0) >> 4;
                uint8_t y1 = forwardMatrix[fm][t] & 0x0F;

                uint8_t l1 = L_Table(x1,y1);

                uint8_t max = (l + l1) > 255 ? (l + l1) - 255: (l+l1); 

                int x2 = (max & 0xF0) >> 4;
                int y2 = (max & 0x0F);

                uint8_t e = E_Table(x2,y2);

                tmp[t] = x==0 && y==0 ? 0:e;
            }

            uint8_t d = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];
            c[vc] = (d & 0xF0) >> 4;
            c[vc+1] = (d & 0x0F);
        }
    }
    
    HexType out(c,32);

    return out;
}

HexType
Encrypt::XorBlocks(HexType pt, HexType pb)
{
    //length of plaintext block
    size_t pt_l = pt.GetHexWords().l;
    //length of prev block
    size_t pb_l = pb.GetHexWords().l;

    Words plain_text;
    plain_text.w = (uint8_t*) malloc (pt_l * sizeof(uint8_t));
    memcpy (plain_text.w, pt.GetHexWords().w, pt_l);

    Words prev_block;
    prev_block.w = (uint8_t*) malloc (pb_l * sizeof(uint8_t));
    memcpy (prev_block.w, pb.GetHexWords().w, pb_l);

    Words xor_result;
    xor_result.w = (uint8_t*) malloc (pb_l * sizeof(uint8_t));
    xor_result.l = pb_l;    

    for ( size_t i = 0; i < pt_l; i++)
    {
        xor_result.w[i] = plain_text.w[i] ^ prev_block.w[i];
    }

    HexType result = HexType (xor_result);

    return result;	
}

void
Encrypt::Print (void)
{
    cipherText->Print();
}

HexType
Encrypt::GetCipherText (void)
{
    return (*cipherText);
}


//ECB class
EncryptECB::EncryptECB (HexType i, std::vector<HexType> ks)
{
    plainText = (HexType*) malloc (1 * sizeof(HexType));
    *plainText = i;
    keySchedule = ks;
}

EncryptECB::EncryptECB ()
{
}

EncryptECB::~EncryptECB ()
{
}

HexType
EncryptECB::EncryptInputECB (HexType inh, std::vector<HexType> ks)
{
    inh.PadToBlocksize(32);

    uint8_t *c_in = inh.GetHexWords().w;
    size_t total_length = inh.GetHexWords().l;

    //ct will hold the ciphertext
    uint8_t *ct = (uint8_t*) malloc (1 * sizeof (uint8_t));
    ct[0] = 0;
    size_t ct_l = 0;

    std::vector<std::string> ct_string;
    
    for (int i = 0; i < total_length; i+=32)
    {
        uint8_t *m = (uint8_t*)malloc(32 * sizeof(uint8_t));
        
        memcpy(m,c_in+i,32);
        HexType mh = HexType(m,32);
       
        EncryptECB em = EncryptECB(mh,ks);
        em.CreateCipherText();
        HexType pt = em.GetCipherText();

        ct = (uint8_t *) realloc (ct, (32+ct_l)*sizeof(uint8_t));
        memcpy(ct+ct_l, pt.GetHexWords().w, 32);
        ct_l += 32;
    }
    
    //return the encrypted data
    HexType ct_hex = HexType (ct,ct_l);
    return ct_hex;
}


void
EncryptECB::CreateCipherText(void)
{
    int round = 0;
    
    HexType r = KeyAdd (*plainText, keySchedule[round]);
    
    r = RotateBlock (r);
    
    round += 1;
    
    for (; round < 10; round += 1)
    {
        r = ByteSub (r);
        r = ShiftRows (r);
        r = MixCol (r);
        r = KeyAdd (r,RotateBlock(keySchedule[round]));
    }
    
    round = 10;
    
    r = ByteSub (r);
    r = ShiftRows (r);
    HexType rk = RotateBlock(keySchedule[round]);
    r = KeyAdd(r,rk);
    r = RotateBlock(r);
    
    cipherText = (HexType*) malloc (1 * sizeof(HexType));
    *cipherText = r;
}

//CBC class
EncryptCBC::EncryptCBC (HexType i, std::vector<HexType> ks, HexType iv)
{
    plainText = (HexType*) malloc (1 * sizeof(HexType));
    *plainText = i;
    keySchedule = ks;
    initVector = (HexType*) malloc (1 * sizeof(HexType));
    *initVector = iv;
}

EncryptCBC::EncryptCBC ()
{
}

void
EncryptCBC::CreateCipherText(void)
{
    int round = 0;
    
    //the init vector is IV for first block of plain text
    //the init vector is cipher text from prev steps afterwards
    HexType r = XorBlocks (*plainText, *initVector);
    
    r = KeyAdd (r, keySchedule[round]);
    
    r = RotateBlock (r);
    
    round += 1;
    
    for (; round < 10; round += 1)
    {
        r = ByteSub (r);
        r = ShiftRows (r);
        r = MixCol (r);
        r = KeyAdd(r,RotateBlock(keySchedule[round]));
    }
    
    round = 10;
    
    r = ByteSub (r);
    r = ShiftRows (r);
    HexType rk = RotateBlock(keySchedule[round]);
    r = KeyAdd(r,rk);
    r = RotateBlock(r);
    
    cipherText = (HexType*) malloc (1 * sizeof(HexType));
    *cipherText = r;
}

HexType
EncryptCBC::EncryptInputCBC(HexType inh, HexType hiv, std::vector<HexType> ks)
{
    inh.InsertRandomPad();
    inh.PadToBlocksize(32);

    uint8_t *c = inh.GetHexWords().w;
    size_t total_length = inh.GetHexWords().l;

    //ct will hold the ciphertext
    uint8_t *ct = (uint8_t*) malloc (1 * sizeof (uint8_t));
    ct[0] = 0;
    size_t ct_l = 0;
    
    //encrypt funcs are implemented to deal with 16 byte ascii or 32 hex format
    size_t cp_length = 32;

    std::vector<HexType> cipherTexts;
    size_t count_lines = 0;

    for (int i = 0; i < total_length; i+=cp_length)
    {
        uint8_t *m = (uint8_t*)malloc(32 * sizeof(uint8_t));
        
        memcpy(m,c+i,32);
        HexType mh = HexType(m,32);
        
        if (count_lines == 0)
        {
            EncryptCBC et = EncryptCBC (mh,ks,hiv);
            et.CreateCipherText();
            HexType etx = et.GetCipherText();
            cipherTexts.push_back (etx);
            
            ct = (uint8_t *) realloc (ct, (32+ct_l)*sizeof(uint8_t));
            memcpy(ct+ct_l, etx.GetHexWords().w, 32);
            ct_l += 32;
        }
        else
        {
            HexType cur = cipherTexts[count_lines-1];
            EncryptCBC et = EncryptCBC (mh,ks,cur);
            et.CreateCipherText();
            HexType etx = et.GetCipherText();
            cipherTexts.push_back (etx);
            
            ct = (uint8_t *) realloc (ct, (32+ct_l)*sizeof(uint8_t));
            memcpy(ct+ct_l, etx.GetHexWords().w, 32);
            ct_l += 32;
        }
        
        count_lines++;
    }
    
    HexType ct_hex = HexType (ct,ct_l);
    return ct_hex;
}

