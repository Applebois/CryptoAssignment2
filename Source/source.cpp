////////////INCLUDE COLOUR CODE///////////////////
#ifndef _COLORS_
#define _COLORS_
#define RST  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define FRED(x) KRED x RST
#define FGRN(x) KGRN x RST
#define FYEL(x) KYEL x RST
#define FBLU(x) KBLU x RST
#define FMAG(x) KMAG x RST
#define FCYN(x) KCYN x RST
#define FWHT(x) KWHT x RST
#define BOLD(x) "\x1B[1m" x RST
#define UNDL(x) "\x1B[4m" x RST
#endif  /* _COLORS_ */
/////////////END OF INCLUDE COLOR CODE////////////////////


//////////////////INCLUDE LIBRARY//////////////////////////
#include <iostream>
#include <fstream>
#include "cryptopp/seed.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"
///////////////////END OF INCLUDE LIBRARY////////////////////////////

using namespace std;
using namespace CryptoPP;

void Print(const std::string& label, const std::string& val)
{
   std::string encoded;
   StringSource(val, true,
      new HexEncoder(
         new StringSink(encoded)
      ) // HexEncoder
   ); // StringSource
   std::cout << label << ": " << encoded << std::endl;
}

int main(int argc, char** argv)
{

if(argv[1]!=NULL)
{
string mode= argv[1];
if(mode=="-h")
{
	cout<<FBLU("[x]1st parameter -e or -d | Encryption or Decryption")<<endl;
        cout<<FBLU("[y]2nd parameter key file such as | key.txt ")<<endl;
        cout<<FBLU("[z]3rd parameter input file | the file you wish to decrypt or encrypt")<<endl;
        cout<<FBLU("[$]4th parameter output file | the file you wish to save the result/output ")<<endl;
        cout<<FYEL("[x -> y]Encryption Usage: ./seed_cfb -e key.txt plaintext.txt ciphertext.txt")<<endl;
        cout<<FYEL("[y -> x]Decryption Usage: ./seed_cfb -d key.txt encrypted.txt.locked output_to_thatfile.txt")<<endl;
        cout<<FYEL("[File with spacing]Encryption Usage: ./seed_cfb -e key.txt \"sample docs.pdf\" \"encrypted file.pdf\"")<<endl;
        cout<<FYEL("[File with spacing]Decryption Usage: ./seed_cfb -d key.txt \"encrypted file.pdf.locked\" \"recovered file.pdf\"")<<endl;
        cout<<FRED("Written in C++, by Teh Win Sam")<<endl;
        exit(0);

}
}
   if(argv[4]==NULL)
   { 
	cout<<"Program usage failed , -h for help"<<endl;
        exit(0);
   }
   else if(argv[1]==NULL)
   {
	cout<<"Program usage failed , -h for help"<<endl;
	exit(0);
   }else if(argv[2]==NULL)
   {
	cout<<"Program usage failed , -h for help"<<endl;
        exit(0);
   }else if(argv[3]==NULL)
   {
	cout<<"Program usage failed , -h for help"<<endl;
        exit(0);
   }
   AutoSeededRandomPool prng;
   string line;
   string argument = argv[2]; //key file
   ifstream myfile (argument);
   string IVs,keys;
if(myfile.fail())
	{
      cout<<"Key file not found, program quit "<<endl;
        exit(0);
	}
  if (myfile.is_open())
  {
int counter =0;
   while ( getline (myfile,line))
      {
	if (counter==0)
		{
			keys=line;
			counter++;
		}
	if(counter==1)
		{
			IVs=line;
		}
      }
  }
   myfile.close();

   if(IVs.length()!=16)
    {
cout<<"SEED/CFB: "<<IVs.length()<<" is not a valid IV length"<<endl;
exit(0);	
     }
   SecByteBlock key((const byte*)keys.data(), keys.size());
   SecByteBlock iv((const byte*)IVs.data(), IVs.size());


   std::string plain = "";
   std::string cipher, encoded, recovered;

   /*********************************\
   \*********************************/


  string inputfile=argv[3]; // file you supply
  string mode=argv[1];
  ifstream file (inputfile);
     if(file.fail())
     {
        cout<<"Your input file not found , program quit "<<endl;
        exit(0);
     }
   if(mode=="-d")
   {
	int length=inputfile.size();
	if(inputfile[length-7]!='.' || inputfile[length-6]!='l' || inputfile[length-5]!='o' || inputfile[length-4]!='c' || inputfile[length-3]!='k' || inputfile[length-2]!='e' || inputfile[length-1]!='d' )
		{
			cout<<"Invalid input file "<<endl;
			exit(0);
		}
   }
  string inputdata;
  string totaldata;
  if (file.is_open())
  {
int counter=0;
    while(getline (file,inputdata))
     {
		totaldata=totaldata+inputdata+"\n";
     }
    file.close();
  }
//string mode =argv[1];
if(mode=="-e")
{
cout<<"====================================================="<<endl;
cout<<"Encryption mode"<<endl;
cout<<"====================================================="<<endl;
plain=totaldata;
}
else if(mode =="-d")
{
cout<<"====================================================="<<endl;
cout<<"Decryption mode"<<endl;
cout<<"====================================================="<<endl;
cipher=inputdata;
}
else
{
 cout<<"Program usage failed , -h for help"<<endl;
exit(0);
}

if(mode == "-e"){
   try
   {
//      std::cout << "plain text: \n" << plain << std::endl;

      CFB_Mode< SEED >::Encryption e;
      e.SetKeyWithIV(key, key.size(), iv);

      // The StreamTransformationFilter adds padding
      //  as required. ECB and CBC Mode must be padded
      //  to the block size of the cipher.
      StringSource s(plain, true, 
         new StreamTransformationFilter(e,(new HexEncoder(
		new StringSink(cipher)))
         ) // StreamTransformationFilter
      ); // StringSource
   }
   catch(const CryptoPP::Exception& e)
   {
      std::cerr << e.what() << std::endl;
      exit(1);
   }
   Print("key", std::string((const char*)key.begin(), key.size()));
   Print("iv", std::string((const char*)iv.begin(), iv.size()));

   /*********************************\
   \*********************************/

  string outputfile=argv[4];  // file system that generate out [output]
  string deletecommand="rm \""+inputfile;
  deletecommand=deletecommand+"\"";
  system(deletecommand.c_str());
  outputfile=outputfile+".locked";
  cout<<"File Encrypted"<<endl;
  cout<<"The locked file is renamed into --> '"<<outputfile<<"'"<<endl;
  ofstream my (outputfile);
  if (my.is_open())
  {
    my<<cipher;
    my.close();
  }
}
   /*********************************\
   \*********************************/
if(mode =="-d"){

   try
   {
      CFB_Mode< SEED >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      // The StreamTransformationFilter removes
      //  padding as required.
      StringSource s(cipher, true,(new HexDecoder( 
       new StreamTransformationFilter(d,
		new StringSink(recovered)))
       ) // StreamTransformationFilter
      ); // StringSource
   Print("key", std::string((const char*)key.begin(), key.size()));
   Print("iv", std::string((const char*)iv.begin(), iv.size()));

  cout<<"File has been decrypted"<<endl;
  string outputfile=argv[4];
  string deletecommand="rm \""+inputfile;
  deletecommand=deletecommand+"\"";
  system(deletecommand.c_str());
  string totaldecryptdata;
  cout<<"The decrypted file is named as '"<<outputfile<<"'"<<endl;
  ofstream my (outputfile);
  if (my.is_open())
  {
    my << hex<<recovered;
    my.close();
  }
   }
   catch(const CryptoPP::Exception& e)
   {
      std::cerr << e.what() << std::endl;
      exit(1);
   }
}
   return 0;
}
