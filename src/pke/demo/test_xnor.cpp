
#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"
#include "encoding/byteplaintextencoding.h"
#include "encoding/signedintplaintextencoding.h"
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

using namespace std;
using namespace lbcrypto;





typedef Poly PolyType;



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

  int maxBits = 2;

  for (int j = i; j < maxBits; ++j)
  {
	ret.push_back(0); // fill rest with 0s, want 8 bits for each number
  }
  
  reverse(ret.begin(),ret.end());
  return ret;
}




void decryptAndPrint(
	shared_ptr<CryptoContext<PolyType>> cc,
	shared_ptr<Ciphertext<PolyType>> CTextVal,
	LPKeyPair<PolyType> keyPair
	){
	vector<shared_ptr<Ciphertext<PolyType>>> ctextVector = vector<shared_ptr<Ciphertext<PolyType>>>();
	ctextVector.push_back(CTextVal);
	IntPlaintextEncoding ptVal;
	cc->Decrypt(keyPair.secretKey, ctextVector, &ptVal, true);
	cout << "PTVAL:" << ptVal.EvalToInt(1024) << endl;
}





vector<vector<shared_ptr<Ciphertext<PolyType>>>> encryptBitwise(shared_ptr<CryptoContext<PolyType>> cc,
	uint32_t val,
	LPKeyPair<PolyType> keyPair
	){

	cout << "encrypting bitwise" << endl;

	std::vector<uint32_t> bitwisePlaintext = convertToBits(val);

	vector<vector<shared_ptr<Ciphertext<PolyType>>>> thisBitwiseCtext = vector<vector<shared_ptr<Ciphertext<PolyType>>>>();
	for (unsigned int i = 0; i < bitwisePlaintext.size(); ++i)
	{
		// use new encryption for different noise
		if(bitwisePlaintext.at(i) == 1){
			IntPlaintextEncoding encodedValue = IntPlaintextEncoding(1);
			vector<shared_ptr<Ciphertext<PolyType>>> ciphertextValue = cc->Encrypt(keyPair.publicKey, encodedValue, true);
			thisBitwiseCtext.push_back(ciphertextValue);
		}
		else{
			IntPlaintextEncoding encodedValue = IntPlaintextEncoding(0);
			vector<shared_ptr<Ciphertext<PolyType>>> ciphertextValue = cc->Encrypt(keyPair.publicKey, encodedValue, true);
			thisBitwiseCtext.push_back(ciphertextValue);
		}
	}

	return thisBitwiseCtext;
}


shared_ptr<Ciphertext<PolyType>> bitwiseCompareQuery(shared_ptr<CryptoContext<PolyType>> cc, 
	vector<vector<shared_ptr<Ciphertext<PolyType>>>> val1, 
	vector<vector<shared_ptr<Ciphertext<PolyType>>>> val2,
	vector<shared_ptr<Ciphertext<PolyType>>> extractValue,
	LPKeyPair<PolyType> keyPair
	){

	cout << "running a bitwise compare" << endl;

	IntPlaintextEncoding encodedValueZero = IntPlaintextEncoding(0);
	vector<shared_ptr<Ciphertext<PolyType>>> ctext0 = cc->Encrypt(keyPair.publicKey, encodedValueZero, true);


	IntPlaintextEncoding encodedValueOne = IntPlaintextEncoding(1);
	vector<shared_ptr<Ciphertext<PolyType>>> ctext1 = cc->Encrypt(keyPair.publicKey, encodedValueOne, true);


	// IntPlaintextEncoding encodedValueOneMinus = IntPlaintextEncoding(-1);
	// vector<shared_ptr<Ciphertext<PolyType>>> ctext1Minus = cc->Encrypt(keyPair.publicKey, encodedValueOneMinus, true);


	if(val1.size() != val2.size()){
		cout << "Error values are not same length";
		return NULL;
	}


	shared_ptr<Ciphertext<PolyType>> xnorResult = ctext1.at(0);

	for (unsigned int i = 0; i < val1.size(); ++i)
	{

		// cout << "ctext of minux 1 : " << endl; 

		// shared_ptr<Ciphertext<PolyType>> minOne = cc->EvalSub(ctext0.at(0), ctext1.at(0));
		// cout << "got min 1:";
		// decryptAndPrint(cc, minOne, keyPair);

		// do (A x B)+(A' x B')
		// A' = A - 1
		// B' = B - 1
		cout << "run opps in compare" << endl;
		shared_ptr<Ciphertext<PolyType>> val1Bit = val1.at(i).at(0);
		shared_ptr<Ciphertext<PolyType>> val1BitMinus1 = cc->EvalSub(val1Bit, ctext1.at(0));

		// cout << "val 1 bit : ";
		// decryptAndPrint(cc, val1Bit, keyPair);
		// cout << "val 1 bit minus 1 : ";
		// decryptAndPrint(cc, val1BitMinus1, keyPair);

		shared_ptr<Ciphertext<PolyType>> val2Bit = val2.at(i).at(0);
		shared_ptr<Ciphertext<PolyType>> val2BitMinus1 = cc->EvalSub(val2Bit, ctext1.at(0));

		// cout << "val 2 bit : ";
		// decryptAndPrint(cc, val2Bit, keyPair);
		// cout << "val 2 bit minus 1 : ";
		// decryptAndPrint(cc, val2BitMinus1, keyPair);


		shared_ptr<Ciphertext<PolyType>> xnorLeftResult = cc->EvalMult(val1Bit, val2Bit);
		shared_ptr<Ciphertext<PolyType>> xnorrightResult = cc->EvalMult(val1BitMinus1, val2BitMinus1);

		shared_ptr<Ciphertext<PolyType>> xnorResultBoth = cc->EvalAdd(xnorLeftResult, xnorrightResult);

		xnorResult = cc->EvalMult(xnorResult, xnorResultBoth);
	}




	shared_ptr<Ciphertext<PolyType>> res =  cc->EvalMult(xnorResult, extractValue.at(0));
	
	// decryptAndPrint(cc, res, keyPair);
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


	vector<uint32_t> inputValues = {3, 2, 4};

	vector<uint32_t> extractValu = {1, 2, 3};



	// vector<uint32_t> inputValues = {1,2,3,4,5,6};

	// vector<uint32_t> inputValues = {6,2,1,3,5,7};

	// vector<uint32_t> inputValues = {7,2,3,4};

	// vector<uint32_t> inputValues = {7,2,3,4};

	// vector<uint32_t> inputValues = {2,4,5};

	// vector<uint32_t> inputValues = {2,3};

	shared_ptr<CryptoContext<PolyType>> cc;

	vector<shared_ptr<Ciphertext<PolyType>>> encrpytedValues = vector<shared_ptr<Ciphertext<PolyType>>>();

	int plaintextModulus;

	try {

		if(true){
			plaintextModulus = 1024;

			int depth = 4;


			uint64_t cyclotomicOrder = 1024*2;


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


		keyPair = cc->KeyGen();

		cc->EvalMultKeyGen(keyPair.secretKey);


		std::vector<uint32_t> oneVal = vector<uint32_t>();
		oneVal.push_back(1);
		IntPlaintextEncoding encodedOneValue = IntPlaintextEncoding(oneVal);
		vector<shared_ptr<Ciphertext<PolyType>>> ctextOne = cc->Encrypt(keyPair.publicKey, encodedOneValue, true);


		std::vector<uint32_t> zeroVal = vector<uint32_t>();
		zeroVal.push_back(0);
		IntPlaintextEncoding encodedZeroValue = IntPlaintextEncoding(zeroVal);
		vector<shared_ptr<Ciphertext<PolyType>>> ctextZero = cc->Encrypt(keyPair.publicKey, encodedZeroValue, true);


		vector<shared_ptr<Ciphertext<PolyType>>> totalResultVect = cc->Encrypt(keyPair.publicKey, encodedZeroValue, true);

		shared_ptr<Ciphertext<PolyType>> totalResult = totalResultVect.at(0);
		

		std::vector<vector<vector<shared_ptr<Ciphertext<PolyType>>>>> allBitwiseCtext = vector<vector<vector<shared_ptr<Ciphertext<PolyType>>>>>();
		for (unsigned int i = 0; i < inputValues.size(); ++i)
		{

			allBitwiseCtext.push_back(encryptBitwise(cc, inputValues.at(i), keyPair));
		}


		vector<vector<shared_ptr<Ciphertext<PolyType>>>> allEncryptedValsToExtract = vector<vector<shared_ptr<Ciphertext<PolyType>>>>();
		for (unsigned int i = 0; i < extractValu.size(); ++i)
		{
			IntPlaintextEncoding encodedValue = IntPlaintextEncoding(extractValu.at(i));
			vector<shared_ptr<Ciphertext<PolyType>>> ciphertextValue = cc->Encrypt(keyPair.publicKey, encodedValue, true);
			allEncryptedValsToExtract.push_back(ciphertextValue);
		}

		// re-encrypt the value	we want to extract

		uint32_t queryVal = inputValues.at(1);
		std::vector<uint32_t> bitwiseQueryVal = convertToBits(queryVal);
		vector<vector<shared_ptr<Ciphertext<PolyType>>>> bitwiseQueryValCText = encryptBitwise(cc, inputValues.at(1), keyPair);


		for (unsigned int i = 0; i < allBitwiseCtext.size(); ++i)
		{
			shared_ptr<Ciphertext<PolyType>> queryResult = bitwiseCompareQuery(cc, allBitwiseCtext.at(i), bitwiseQueryValCText, allEncryptedValsToExtract.at(i), keyPair);

			cout << "totalResult BEFORE ADD : " ;
			decryptAndPrint(cc, totalResult, keyPair);

			cout << "QUERY RESULT : " ;
			decryptAndPrint(cc, queryResult, keyPair);
			cout << endl;
			totalResult = cc->EvalAdd(totalResult, queryResult);

			cout << "totalResult AFTER ADD : " ;
			decryptAndPrint(cc, totalResult, keyPair);

		}




		vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult1 = vector<shared_ptr<Ciphertext<PolyType>>>();
		ctextVectorResult1.push_back(totalResult);

		IntPlaintextEncoding ptValue1;
		cc->Decrypt(keyPair.secretKey, ctextVectorResult1, &ptValue1, true);

		cout << "FINAL " << ptValue1.EvalToInt(plaintextModulus) << endl;

		exit(1);

	}  catch (const std::exception &e){
		std::cout << "Exception caught while encrypting " << e.what() << endl;
		
	}

}


