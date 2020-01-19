#include <fstream>
#include <string>
#include <sstream>
#include "encrypt.h"

HexType
OneByteShort (int bs)
{
    char akey[17]="YELLOW SUBMARINE";
    AsciiType aak = AsciiType (akey,16);
    HexType key = aak.GetHex();
    KeyType kt = KeyType (key);
    std::vector<HexType> ks = kt.GetKeySchedule();

    int str_len = bs; 
    std::string a = "";
    std::string b = "";

    for (int i = 0; i < str_len-1 ; i++)
    {   
        a+= "A";
    }

    AsciiType aa = AsciiType ((char*)a.c_str(),bs-1);
    std::cout << " print ascii " << std::endl;
    aa.Print();
    std::cout << std::endl;
    HexType inh = aa.GetHex();
    EncryptECB tmp;
    HexType ct = tmp.EncryptInputECB (inh,ks);

    return ct;
}


std::vector<std::pair<std::string,HexType>>
CreateDictionary (int bs)
{
    //generate key
    char akey[17]="YELLOW SUBMARINE";
    AsciiType aak = AsciiType (akey,16);
    HexType key = aak.GetHex();
    KeyType kt = KeyType (key);
    std::vector<HexType> ks = kt.GetKeySchedule();

    //random multiplier of 3, therefor 3 16 byte blocks are formed
    //the +1  will force the pkcs#7 to pad the string
    //pkcs7 pads the string with know values
    //the know values will be used to construct a dictionary of the encryption output
    int str_len = bs; 
    std::string a = "";

    for (int i = 0; i < str_len-1 ; i++)
    {   
        a+= "A";
    }

    AsciiType aa = AsciiType ((char*)a.c_str(),bs-1);
    HexType inh = aa.GetHex();

    std::vector<std::pair<std::string,HexType>> dictionary;

    for (int i = 0; i < 256 ; i++)
    {
        Words byte_pad;
        byte_pad.w = (uint8_t *) malloc (2 * sizeof (uint8_t));
        byte_pad.l = 2;

        byte_pad.w[0] = (i & 0xF0) >> 4;
        byte_pad.w[1] = (i & 0x0F);

        HexType ph = HexType (byte_pad);
        HexType inhh = inh;
        inhh.InsertStringPad (ph);
        
        std::string b = inhh.SerializeString();

        EncryptECB tmp;
        HexType ct = tmp.EncryptInputECB (inhh,ks);
        dictionary.push_back (std::make_pair(b,ct));
    }

    return dictionary;
}


std::vector<std::pair<std::string,HexType>>
CreateDictionaryUnknownString (int bs)
{
    //read and append unknown string to plaintext
    std::string p_in = "b64pad.txt";
    FileReader pad_in = FileReader (p_in,false);
    HexType padh = pad_in.GetBase64().GetHex();

    char akey[17]="YELLOW SUBMARINE";
    AsciiType aak = AsciiType (akey,16);
    HexType key = aak.GetHex();
    KeyType kt = KeyType (key);
    std::vector<HexType> ks = kt.GetKeySchedule();

    int str_len = bs; 
    std::string a = "";

    for (int i = 0; i < str_len-1 ; i++)
    {   
        a+= "A";
    }

    AsciiType aa = AsciiType ((char*)a.c_str(),bs-1);
    HexType inh = aa.GetHex();

    Words wpadh = padh.GetHexWords();
    
    std::vector<std::pair<std::string,HexType>> dictionary;
    for (int i = 0; i < wpadh.l; i+=2)
    {
        Words byte_pad;
        byte_pad.w = (uint8_t *) malloc (2 * sizeof (uint8_t));
        byte_pad.l = 2;

        byte_pad.w[0] = wpadh.w[i];
        byte_pad.w[1] = wpadh.w[i+1];

        HexType ph = HexType (byte_pad);
        HexType inhh = inh;
        inhh.InsertStringPad (ph);

        std::string b = inhh.SerializeString();

        EncryptECB tmp;
        HexType ct = tmp.EncryptInputECB (inhh,ks);
        dictionary.push_back (std::make_pair(b,ct));
    }   

    return dictionary;
}

void
CreatePlainText (std::vector<std::pair<std::string, HexType>> d1, 
                 std::vector<std::pair<std::string, HexType>> d2
                )
{
    std::string clipped_str;

    for (auto it2 = d2.begin(); it2 != d2.end(); it2++)
    {
        for (auto it1 = d1.begin(); it1 != d1.end(); it1++)
        {
            if (it2->second.SerializeString() == it1->second.SerializeString())
            {
                size_t str_len = it1->first.size();
                clipped_str += it1->first[str_len-2];
                clipped_str += it1->first[str_len-1];
            }
        }
    }

    HexType aa = HexType ((char*)clipped_str.c_str(),clipped_str.size());
    AsciiType out = aa.GetAscii();
    std::cout << " \n printing plaintext payload " << std::endl;
    out.Print();
    std::cout << std::endl;
}


int
FindBlocksize()
{
    char akey[17]="YELLOW SUBMARINE";
    AsciiType aak = AsciiType (akey,16);

    HexType key = aak.GetHex();
    KeyType kt = KeyType (key);
    std::vector<HexType> ks = kt.GetKeySchedule();

    std::string a = "";
    AsciiType aa = AsciiType ((char*)a.c_str(),0);
    HexType inh = aa.GetHex();

    std::vector<std::pair<int, int>> in_out_sizes;

    EncryptECB tmp;
    HexType ct = tmp.EncryptInputECB (inh,ks);

    int cur_bs = ct.GetHexWords().l;
    int prev_bs = 0;
    in_out_sizes.push_back(std::make_pair(0, cur_bs));

    for (int i = 1; i < 256; i++)
    {
        a += "A";
        AsciiType aa = AsciiType ((char*)a.c_str(),i);
        HexType inh = aa.GetHex();
        EncryptECB tmp;
        HexType ct = tmp.EncryptInputECB (inh,ks);

        cur_bs = ct.GetHexWords().l;
        
        in_out_sizes.push_back(std::make_pair(i, cur_bs));

        prev_bs = in_out_sizes[i-1].second;
        if (cur_bs - prev_bs > 0 && prev_bs > 0)
        {
            //HexType length is 2x larger, therefor must divide by 2
            return (cur_bs - prev_bs)/2;
        }
    }

    return 0;
}

int main ()
{
    //read plaintext that will be encrypted with unknown key
    std::string f_in = "12.txt";
    FileReader file_in = FileReader (f_in,true);
    HexType inh = file_in.GetAscii().GetHex();

    //read and append unknown string to plaintext
    std::string p_in = "b64pad.txt";
    FileReader pad_in = FileReader (p_in,false);
    HexType padh = pad_in.GetBase64().GetHex();
    inh.InsertStringPad (padh);

    //random unknown key
    char akey[17]="YELLOW SUBMARINE";
    AsciiType aak = AsciiType (akey,16);

    //generated keyschedule
    KeyType kt = KeyType(true);
    std::vector<HexType> ks = kt.GetKeySchedule();

    EncryptECB tmp;
    HexType ct = tmp.EncryptInputECB (inh,ks);

    std::cout << " \n is ECB " << ct.isECB() << std::endl;

    int kbs=FindBlocksize();

    std::vector<std::pair<std::string,HexType>> dt = CreateDictionary (kbs);
    std::vector<std::pair<std::string,HexType>> dtu = CreateDictionaryUnknownString (kbs);

    CreatePlainText (dt, dtu);
}
