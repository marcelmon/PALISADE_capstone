
#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

#include <cstdlib>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>



#include <cstdio>
#include <string>
#include <sstream>

#include <typeinfo>


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>


using namespace std;
using namespace lbcrypto;


typedef Poly PolyType;



Ciphertext<PolyType> ctext0;
Ciphertext<PolyType> ctext1;

Plaintext encodedValueOne;
Plaintext encodedValueZero;


vector<uint32_t> convertToBits(uint32_t x) {
  vector<uint32_t> ret;

  int i = 0;
  while(x) {
  	i++;
    if (x&1)
      ret.push_back(1);
    else
      ret.push_back(0);
    x>>=1;  
  }

  int maxBits = 3;

  for (int j = i; j < maxBits; ++j)
  {
	ret.push_back(0); // fill rest with 0s, want 8 bits for each number
  }
  
  reverse(ret.begin(),ret.end());
  return ret;
}




void decryptAndPrint(
	CryptoContext<PolyType> cc,
	Ciphertext<PolyType> CTextVal,
	LPKeyPair<PolyType> keyPair
	){

	Plaintext ptVal;
	cc->Decrypt(keyPair.secretKey, CTextVal, &ptVal);
	// cout << "PTVAL:" << ptVal.EvalToInt(1024) << endl;
}






vector<Ciphertext<PolyType>> encryptBitwise(CryptoContext<PolyType> cc,
	uint32_t val,
	LPKeyPair<PolyType> keyPair
	){

	// cout << "encrypting bitwise" << endl;

	std::vector<uint32_t> bitwisePlaintext = convertToBits(val);

	vector<Ciphertext<PolyType>> thisBitwiseCtext = vector<Ciphertext<PolyType>>();
	for (unsigned int i = 0; i < bitwisePlaintext.size(); ++i)
	{
		// use new encryption for different noise
		if(bitwisePlaintext.at(i) == 1){
			Ciphertext<PolyType> ciphertextValue = cc->Encrypt(keyPair.publicKey, encodedValueOne);
			thisBitwiseCtext.push_back(ciphertextValue);
		}
		else{
			Ciphertext<PolyType> ciphertextValue = cc->Encrypt(keyPair.publicKey, encodedValueZero);
			thisBitwiseCtext.push_back(ciphertextValue);
		}
	}

	return thisBitwiseCtext;
}


Ciphertext<PolyType> bitwiseCompareQuery(CryptoContext<PolyType> cc, 
	vector<Ciphertext<PolyType>> val1, 
	vector<Ciphertext<PolyType>> val2,
	Ciphertext<PolyType> extractValue,
	LPKeyPair<PolyType> keyPair
	){

	// cout << "running a bitwise compare" << endl;



	// IntPlaintextEncoding encodedValueOneMinus = IntPlaintextEncoding(-1);
	// vector<shared_ptr<Ciphertext<PolyType>>> ctext1Minus = cc->Encrypt(keyPair.publicKey, encodedValueOneMinus, true);


	if(val1.size() != val2.size()){
		cout << "Error values are not same length";
		return NULL;
	}


	Ciphertext<PolyType> xnorResult = ctext1;

	for (unsigned int i = 0; i < val1.size(); ++i)
	{

		// cout << "ctext of minux 1 : " << endl; 

		// shared_ptr<Ciphertext<PolyType>> minOne = cc->EvalSub(ctext0.at(0), ctext1.at(0));
		// cout << "got min 1:";
		// decryptAndPrint(cc, minOne, keyPair);

		// do (A x B)+(A' x B')
		// A' = A - 1
		// B' = B - 1
		// cout << "run opps in compare" << endl;
		Ciphertext<PolyType> val1Bit = val1.at(i);
		Ciphertext<PolyType> val1BitMinus1 = cc->EvalSub(val1Bit, ctext1);

		// cout << "val 1 bit : ";
		// decryptAndPrint(cc, val1Bit, keyPair);
		// cout << "val 1 bit minus 1 : ";
		// decryptAndPrint(cc, val1BitMinus1, keyPair);

		Ciphertext<PolyType> val2Bit = val2.at(i);
		Ciphertext<PolyType> val2BitMinus1 = cc->EvalSub(val2Bit, ctext1);

		// cout << "val 2 bit : ";
		// decryptAndPrint(cc, val2Bit, keyPair);
		// cout << "val 2 bit minus 1 : ";
		// decryptAndPrint(cc, val2BitMinus1, keyPair);


		Ciphertext<PolyType> xnorLeftResult = cc->EvalMult(val1Bit, val2Bit);
		Ciphertext<PolyType> xnorrightResult = cc->EvalMult(val1BitMinus1, val2BitMinus1);

		Ciphertext<PolyType> xnorResultBoth = cc->EvalAdd(xnorLeftResult, xnorrightResult);

		xnorResult = cc->EvalMult(xnorResult, xnorResultBoth);
	}

	// cout << "VAL1 BITS : ";
	for (unsigned int i = 0; i < val1.size(); ++i)
	{
		decryptAndPrint(cc, val1.at(i), keyPair);
	}
	// cout << endl << endl;


	// cout << "VAL2 BITS : ";
	for (unsigned int i = 0; i < val2.size(); ++i)
	{
		decryptAndPrint(cc, val2.at(i), keyPair);
	}
	// cout << endl << endl;


	// cout << "EXTRACT VAL : ";
	// decryptAndPrint(cc, extractValue.at(0), keyPair);
	// cout << endl;

	Ciphertext<PolyType> res =  cc->EvalMult(xnorResult, extractValue);
	
	// cout << "RES : ";
	decryptAndPrint(cc, res, keyPair);
	cout << endl;
	return res;
}





int main(int argc, char *argv[]) {



	// BigInteger firstPrime = lbcrypto::FirstPrime<BigInteger>(301, 16384);

	// BigInteger rootOfU = lbcrypto::RootOfUnity<BigInteger>(16384, firstPrime);

	// cout << "FIRST PRIME "  << firstPrime << endl;


	// cout << "ROOT OF UNITY " <<  rootOfU << endl;
		
	// exit(1);

	LPKeyPair<PolyType> keyPair;

	// vector<uint32_t> inputValues = {1,1,1,1,1,1};

	// vector<uint32_t> inputValues = {2,44,9,22,3,2,2,3};

	// vector<uint32_t> extractValu = {1, 2,3, 4,5,6,7,8};


	vector<uint32_t> inputValues = {1, 2,  3, 4,  5,  6, 7};

	vector<uint32_t> extractValu = {7, 25, 3, 7 ,12, 15, 19};


	// vector<uint32_t> inputValues = {1, 2};

	// vector<uint32_t> extractValu = {7, 25};


	uint32_t queryVal = inputValues.at(4);

	// vector<uint32_t> inputValues = {1,2,3,4,5,6};

	// vector<uint32_t> inputValues = {6,2,1,3,5,7};

	// vector<uint32_t> inputValues = {7,2,3,4};

	// vector<uint32_t> inputValues = {7,2,3,4};

	// vector<uint32_t> inputValues = {2,4,5};

	// vector<uint32_t> inputValues = {2,3};

	CryptoContext<PolyType> cc;

	vector<Ciphertext<PolyType>> encrpytedValues = vector<Ciphertext<PolyType>>();

	int plaintextModulus;



	try {

		if(true){
			plaintextModulus = 1024;

			int depth = 4;


			uint64_t cyclotomicOrder = 1024*2/16;


			/// SOLINAS PRIME
			// BigInteger modulusBigInt = PolyType::Integer("2147352577");
			// BigInteger rootOfUnityBigInt = PolyType::Integer("1539779042");


			BigInteger modulusBigInt = PolyType::Integer("2147352577");
			BigInteger rootOfUnityBigInt = PolyType::Integer("461230749");

			// BigInteger modulusBigInt = PolyType::Integer("2147473409");
			// BigInteger rootOfUnityBigInt = PolyType::Integer("256290069");

			usint relinWindow = 1;
			float stDev = 3;

			MODE mode = RLWE;

			shared_ptr<typename PolyType::Params> parms;

			parms.reset( new typename PolyType::Params(cyclotomicOrder,
									modulusBigInt,
									rootOfUnityBigInt));

			cc = CryptoContextFactory<PolyType>::genCryptoContextSHIELD(
				parms, plaintextModulus, relinWindow, stDev, mode, depth);

			cc->Enable(ENCRYPTION);
			cc->Enable(SHE);
		}
		else {
			
		}
			


		
		
		// cout << "ddddd";
		// vector<vector<unique_ptr<PolyType>>> some_data = vector<vector<unique_ptr<PolyType>>>();
		// cout << "eeeee";
		// unique_ptr<PolyType> newPoly = make_unique<PolyType>(parms, EVALUATION, true);

		// cout << "cccccc";
		// newPoly->SetValAtIndex(0, 5);

		// cout << "AHAHAHA";

		// some_data.push_back(vector<unique_ptr<PolyType>>());

		// cout << "fffff";

		// some_data[0].push_back(std::move(newPoly));
		// cout << "bbbbbbbb";
		// unique_ptr<PolyType> newPoly2 = make_unique<PolyType>(parms, EVALUATION, true);
		// newPoly2->SetValAtIndex(0, 8);
		
		// some_data[0].push_back(std::move(newPoly2));


		// exit(1);



	} catch (const std::exception &e){
		std::cout << "Exception caught creating crypto context : " << e.what() << endl;
	}


	try{


		cout << "Generate public-private keypair" << endl;
		keyPair = cc->KeyGen();

		cc->EvalMultKeyGen(keyPair.secretKey);


		encodedValueZero = cc->MakeIntegerPlaintext(0);
		ctext0 = cc->Encrypt(keyPair.publicKey, encodedValueZero);


		encodedValueOne = cc->MakeIntegerPlaintext(1);
		ctext1 = cc->Encrypt(keyPair.publicKey, encodedValueOne);




		// cout << "total result inst." << endl;
		Ciphertext<PolyType> totalResult = cc->Encrypt(keyPair.publicKey, encodedValueZero);

		
		cout << "Encrypting all key value pairs." << endl;

		// cout << "enc bitwise ctext" << endl;
		/*
			each key is stored as a value of encrypted bits

			vector<
				vector<ctext_bit_1, ctext_bit_2,..>,
				vector<ctext_bit_1, ctext_bit_2,..>,
				vector<ctext_bit_1, ctext_bit_2,..>
			>
		*/
		vector<vector<Ciphertext<PolyType>>> allBitwiseCtext = vector<vector<Ciphertext<PolyType>>>();
		for (unsigned int i = 0; i < inputValues.size(); ++i)
		{

			cout << "Encrypting key from  key->value pair : (" << inputValues.at(i) << " : " << extractValu.at(i) << ")" <<endl;

			allBitwiseCtext.push_back(encryptBitwise(cc, inputValues.at(i), keyPair));
		}


		// cout << "enc vals to ctext" << endl;
		vector<Ciphertext<PolyType>> allEncryptedValsToExtract = vector<Ciphertext<PolyType>>();
		for (unsigned int i = 0; i < extractValu.size(); ++i)
		{

			cout << "Encrypting value from  key->value pair : (" << inputValues.at(i) << " : " << extractValu.at(i) << ")" <<endl;

			Plaintext encodedValue = cc->MakeIntegerPlaintext(extractValu.at(i));
			Ciphertext<PolyType> ciphertextValue = cc->Encrypt(keyPair.publicKey, encodedValue);
			allEncryptedValsToExtract.push_back(ciphertextValue);
		}

		// re-encrypt the value	we want to extract
		cout << endl;
		usleep(3000000);
		cout << "Encrypting query key : " << queryVal << endl << endl;
		vector<Ciphertext<PolyType>> bitwiseQueryValCText = encryptBitwise(cc, queryVal, keyPair);



		cout << "Searching all encrypted key:value pairs for query key : "<< queryVal << endl << endl;
		for (unsigned int i = 0; i < allBitwiseCtext.size(); ++i)
		{

			cout << "Searching.." << endl;
			Ciphertext<PolyType> queryResult = bitwiseCompareQuery(cc, allBitwiseCtext.at(i), bitwiseQueryValCText, allEncryptedValsToExtract.at(i), keyPair);

			// cout << "totalResult BEFORE ADD : " ;
			// decryptAndPrint(cc, totalResult, keyPair);

			// cout << "QUERY RESULT : " ;
			// decryptAndPrint(cc, queryResult, keyPair);
			// cout << endl;
			totalResult = cc->EvalAdd(totalResult, queryResult);

			// cout << "totalResult AFTER ADD : " ;
			// decryptAndPrint(cc, totalResult, keyPair);

		}


		Plaintext ptValue1;
		cc->Decrypt(keyPair.secretKey, totalResult, &ptValue1);

		cout << "Extracted database value : " << ptValue1 << endl;

		exit(1);

	}  catch (const std::exception &e){
		std::cout << "Exception caught while encrypting " << e.what() << endl;
		
	}

}


