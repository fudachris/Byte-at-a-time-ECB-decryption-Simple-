#include "var-type.h"

//ASCII class
AsciiType::AsciiType (char *a, size_t len)
{
    ascii.w = (uint8_t *) malloc (len * sizeof (uint8_t));
    memcpy(ascii.w, a, len);
    ascii.l = len;
}

AsciiType::AsciiType(Words a)
{
    ascii.l = a.l;
    ascii.w = (uint8_t *) malloc (a.l * sizeof (uint8_t));
    memcpy (ascii.w, a.w, a.l);
}

AsciiType::AsciiType (void)
{
}

Words
AsciiType::GetAsciiWords (void)
{
    return ascii;
}

HexType
AsciiType::GetHex (void)
{
    size_t ascii_length = ascii.l;
    size_t hex_length = 2 * ascii_length;

    Words tmp;
    tmp.l = hex_length;

    tmp.w = (uint8_t *) malloc (hex_length * sizeof (uint8_t));
     
    for (size_t i = 0, j = 0 ; j < hex_length; i++, j+=2)
    {
        tmp.w[j] = ((ascii.w[i]) & 0xF0) >> 4; 
        tmp.w[j+1] = (ascii.w[i] & 0x0F);
    }

    hex = (HexType*) malloc (1 * sizeof(HexType));
    *hex = HexType(tmp);
    return (*hex);
}

Base64Type
AsciiType::GetBase64 (void)
{
    HexType h = HexType(*hex);
    b64 = (Base64Type*) malloc (1 * sizeof (Base64Type));
    *b64 = (h.GetBase64 ());    
    return (*b64);
}

void
AsciiType::Print (void)
{
    for (size_t i = 0; i < ascii.l; i++)
    {
        printf("%c",ascii.w[i]);
    }
}

//BASE64 class
Base64Type::Base64Type(char *b, size_t len)
{
    size_t bl = len;

    if (bl % 2 != 0)
    {
        std::cout << "\nBase64Type init. error: length should be even " << std::endl;
        b64.w = (uint8_t *) malloc (2 * sizeof (uint8_t));
        b64.w[0] = '0';
        b64.w[1] = '0';
    }
    else
    {
        b64.w = (uint8_t *) malloc (bl * sizeof (uint8_t));

        for (size_t i = 0; i < len; i++)
        {
            b64.w[i] =  GetBase64Value (b[i]);
        }

        b64.l = bl;
    }
}

Base64Type::Base64Type(uint8_t *b, size_t len)
{
    size_t bl = len;

    if (bl % 2 != 0)
    {
        std::cout << "\nBase64Type init. error: length should be even " << std::endl;
        b64.w = (uint8_t *)malloc (2 * sizeof (uint8_t));
        b64.w[0] = 0;
        b64.w[1] = 0;
    }
    else 
    {
        b64.w = (uint8_t *) malloc (bl * sizeof (uint8_t));
        memcpy (b64.w,b,bl);

        b64.l = bl;
    }
}

Base64Type::Base64Type(Words b)
{
    size_t len = b.l;
    b64.l = len;
    b64.w = (uint8_t *) malloc (len * sizeof(uint8_t));
    memcpy (b64.w, b.w, len);
}

Base64Type::Base64Type(void)
{
}

Words
Base64Type::GetBase64Words (void)
{
    return b64;
}

HexType
Base64Type::GetHex (void)
{
    size_t b64_length = b64.l;

    int count = 0;

    count += b64.w[b64_length-1] == 64? 64 : 0;
    count += b64.w[b64_length-2] == 64? 64 : 0;

    size_t hex_length = (b64_length * 3)/2;

    Words tmp;
    tmp.l = hex_length;

    tmp.w = (uint8_t *) malloc (hex_length * sizeof(uint8_t));
    size_t i = 0, j = 0;
    for (; i < b64_length; i+=2, j +=3 )
    {
        uint8_t b0 = b64.w[i];
        uint8_t b1 = b64.w[i+1];

        b0 = b0 == 64 ? 255 : b0;
        b1 = b1 == 64 ? 255 : b1;
            
        uint8_t h0 = (b0 & 0x3C) >> 2;
        uint8_t h1 = (b0 & 0x03) << 2 | (b1 & 0x30) >> 4;
        uint8_t h2 = b1 & 0x0F;

        tmp.w[j] = h0;
        tmp.w[j+1] = h1;
        tmp.w[j+2] = h2;
    }

    hex = (HexType*) malloc (1 * sizeof(HexType));
    
    if (count == 64 || count == 128)
    {     
        size_t h_length = hex_length  - 2 * (count/64);
        Words h;
        h.w = (uint8_t *) malloc (h_length * sizeof(uint8_t));
        memcpy (h.w,tmp.w, h_length);
        h.l = h_length;
        *hex = HexType(h);
        return (*hex);
    }

    *hex = HexType(tmp);
    return (*hex);
}

AsciiType
Base64Type::GetAscii (void)
{
    HexType h = GetHex();
    ascii = (AsciiType*) malloc (1 * sizeof(AsciiType));
    *ascii = (h.GetAscii());
    return (*ascii);
}

void
Base64Type::Print (void)
{
    for (size_t i = 0; i < b64.l; i++)
    {
        printf("%c",GetBase64Char(b64.w[i]));
    }
}

//HEX Class
HexType::HexType(char *input, size_t len)
{
    size_t hl = len;

    if (hl % 2 != 0)
    {
        std::cout << "\nHexType init. error: length should be even " << std::endl;
        hex.w = (uint8_t *)malloc (2 * sizeof (uint8_t));
        hex.w[0] = 0;
        hex.w[1] = 0;
    }
    else 
    {
        hex.w = (uint8_t *) malloc (hl * sizeof (uint8_t));

        for (size_t i = 0; i < len; i++)
        {
            hex.w[i] = GetHexValue (input[i]);
        }

        hex.l = hl;
    }
}

HexType::HexType(uint8_t *input, size_t len)
{
    size_t hl = len;

    if (hl % 2 != 0)
    {
        std::cout << "\nHexType init. error: length should be even " << std::endl;
        hex.w = (uint8_t *)malloc (2 * sizeof (uint8_t));
        hex.w[0] = 0;
        hex.w[1] = 0;
    }
    else 
    {
        hex.w = (uint8_t *) malloc (hl * sizeof (uint8_t));
        memcpy (hex.w,input,hl);
        hex.l = hl;
    }
}

HexType::HexType(Words h)
{
    size_t len = h.l;
    hex.l = len;

    hex.w = (uint8_t *) malloc (len * sizeof(uint8_t));
    memcpy (hex.w, h.w, len);
}

HexType::HexType(void)
{
}

Words
HexType::GetHexWords (void)
{
    return hex;
}

AsciiType
HexType::GetAscii (void)
{
    size_t length = hex.l;
    length /= 2;    //ascii will be 0.5 length of hex

    Words tmp;

    tmp.w = (uint8_t *) malloc (length * sizeof(uint8_t));

    size_t j = 0;

    for (size_t i = 0; j < length; i+=2, j++)
    {                              
        tmp.w[j] = ((hex.w[i]) & 0x0F) << 4 | ((hex.w[i+1]) & 0x0F);
    }

    tmp.l = length;

    ascii = (AsciiType*) malloc (1 * sizeof(AsciiType));
    *ascii = (AsciiType(tmp));
    return (*ascii);
}

Base64Type
HexType::GetBase64 (void)
{
    AsciiType bytes = GetAscii();
    Words ab = bytes.GetAsciiWords();
    size_t length = ab.l;
    size_t pad = length % 3 > 0 ? (3 - length % 3):0;

    length += pad;

    size_t b64_length = (length * 4) / 3;
    
    uint8_t pad_str[2];
    pad_str[0] = 0;
    pad_str[1] = 0;

    ab.w = (uint8_t *) realloc (ab.w, length * sizeof(uint8_t));
    memcpy(ab.w+length-pad, pad_str, pad);

    Words tmp;
    tmp.w = (uint8_t *) malloc (b64_length * sizeof(uint8_t));
    tmp.l = b64_length;

    for (size_t i = 0, j = 0; i < b64_length; i+= 4, j+=3)
    {
        tmp.w[i] = (ab.w[j] & 0xFC) >> 2;
        tmp.w[i+1] = (ab.w[j] & 0x03) << 4 | (ab.w[j+1] & 0xF0) >> 4;
        tmp.w[i+2] = (ab.w[j+1] & 0x0F) << 2 | (ab.w[j+2] & 0xC0) >> 6;
        tmp.w[i+3] = (ab.w[j+2] & 0x3F);
    }

    if (pad == 1)
    {
        tmp.w[b64_length-1] = 64;
    }

    if (pad == 2)
    {
        tmp.w[b64_length-1] = 64;
        tmp.w[b64_length-2] = 64;
    }

    b64 = (Base64Type*) malloc (1 * sizeof (Base64Type));
    *b64 = Base64Type(tmp);
    return (*b64);
}

void
HexType::Print(void)
{
    for (size_t i = 0; i < hex.l; i++)
    {
        printf("%x",hex.w[i]);
    }
}


void 
HexType::InsertStringPad (HexType pad)
{
    Words padd_pt;
    padd_pt.l = hex.l + pad.GetHexWords().l;
    padd_pt.w = (uint8_t*) malloc (padd_pt.l * sizeof(uint8_t));

    memcpy (padd_pt.w, hex.w, hex.l);
    memcpy (padd_pt.w + hex.l, pad.GetHexWords().w, pad.GetHexWords().l);
    hex = padd_pt;
}

//pad random 5 - 10 bytes at the beg/end of pt
void
HexType::InsertRandomPad (void)
{
    //lenght of header pad
    int pad_h_l = 5 + ( std::rand() % ( 10 - 5 + 1 ) );
    //length of tail pad
    int pad_t_l = 5 + ( std::rand() % ( 10 - 5 + 1 ) );

    PadHead(2*pad_h_l);
    PadTail(2*pad_t_l);
}

void
HexType::PadHead (int pad_l)
{
    Words padd_pt;
    padd_pt.l = hex.l + pad_l;
    padd_pt.w = (uint8_t*) malloc ((padd_pt.l)*(sizeof(uint8_t)));

    for (int i = 0; i < pad_l; i+=2)
    {
        uint8_t a = 0 + ( std::rand() % ( 15 - 0 + 1 ) );
        uint8_t b = 0 + ( std::rand() % ( 15 - 0 + 1 ) );

        padd_pt.w[i] = a;
        padd_pt.w[i+1] = b;
    }
    
    memcpy (padd_pt.w + pad_l, hex.w, hex.l);
    hex = padd_pt;
}   

void
HexType::PadTail (int pad_l)
{
    Words padd_pt;
    padd_pt.l = hex.l + pad_l;
    padd_pt.w = (uint8_t*) malloc ((padd_pt.l)*(sizeof(uint8_t)));

    memcpy (padd_pt.w, hex.w, hex.l);

    for (int i = hex.l; i < padd_pt.l; i+=2)
    {
        uint8_t a = 0 + ( std::rand() % ( 15 - 0 + 1 ) );
        uint8_t b = 0 + ( std::rand() % ( 15 - 0 + 1 ) );

        padd_pt.w[i] = a;
        padd_pt.w[i+1] = b;
    }

    hex = padd_pt;
}

size_t
HexType::GetPadLength (size_t block_size, size_t input_length)
{
    block_size /= 2;	//bring back block_size to ascii land
    input_length /=2 ;	//back to ascii land
    size_t pad_length = 0;
	//determine the necessary padding
	if (input_length < block_size)
	{
		pad_length = block_size - input_length;
	}
	else if (input_length > block_size)
	{
		pad_length = block_size - (input_length % block_size);
	}
	else //if (input_length == block_size)
	{
		pad_length = block_size;
	}

	//expected padded string length 
	size_t expsl = input_length + (block_size - (input_length % block_size));
	
	if ( expsl != (input_length + pad_length))
	{
		std::cout << "incorrect padded string length " << std::endl;
	}

    return (2*pad_length);
}

void
HexType::PadToBlocksize (size_t bs)
{
    size_t pad_length = 0;	
    size_t input_length = hex.l;	//hex.l was given with hextype in mind, calculating length in ascii land
    size_t block_size = bs;	//bs was given with hextype in mind, calculating size in ascii land

    pad_length = GetPadLength (block_size, input_length);
	
	Words padded_string;
	padded_string.w = (uint8_t *) malloc ((input_length + pad_length) * sizeof (uint8_t));
	padded_string.l = input_length + pad_length;

	memcpy (padded_string.w, hex.w, input_length);
	
    uint8_t pad_word_a = ((pad_length/2) & 0xF0) >> 4;	
    uint8_t pad_word_b = ((pad_length/2) & 0x0F);	
        
	for (size_t i = input_length; i < padded_string.l; i+=2)
 	{
		padded_string.w[i] = pad_word_a;
		padded_string.w[i+1] = pad_word_b;
	}	

    hex = padded_string;
}

std::string
HexType::SerializeString ()
{
    std::string str;

    for (size_t i = 0; i < hex.l; i++)
    {
        str += GetHexChar(hex.w[i]);
    }

    return str;
}

std::string
HexType::SerializeString (int a, int b)
{
    std::string str;

    for (size_t i = a; i < b; i++)
    {
        str += GetHexChar(hex.w[i]);
    }

    return str;
}

int
HexType::isECB (void)
{
    size_t l = hex.l;

    std::vector<std::string> stringarray;

    for (size_t i = 0; i < l ; i+=32)
    {
        std::string khs = SerializeString(i,i+32);
        stringarray.push_back (khs);
    }

    std::sort(stringarray.begin(), stringarray.end());

    std::map<std::string, int> countMap;

    // Iterate over the vector and store the frequency of each element in map
    for (auto & elem : stringarray)
    {
        auto result = countMap.insert(std::pair<std::string, int>(elem, 1));
        if (result.second == false)
        {
            result.first->second++;
        }
    }

    for (auto & elem : countMap)
    {
        // If frequency count is greater than 1 then its a duplicate element
        if (elem.second > 1)
        {
            return 1;
        }
    }

    return 0;
}




