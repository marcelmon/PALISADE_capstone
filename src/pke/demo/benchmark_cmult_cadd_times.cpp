
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

template<class Element>
shared_ptr<Ciphertext<Element>> runMultInARow(shared_ptr<CryptoContext<Element>> cc, vector<shared_ptr<Ciphertext<Element>>> ctexts){
	if(ctexts.size() < 2){
		return NULL;
	}
	shared_ptr<Ciphertext<Element>> currentCtext = ctexts.at(0);
	for(unsigned int i = 1; i < ctexts.size(); i++){
		currentCtext = cc->EvalMult(currentCtext, ctexts.at(i));
	}

	return currentCtext;
}


template<class Element>
shared_ptr<Ciphertext<Element>> runMultInTree(shared_ptr<CryptoContext<Element>> cc, vector<shared_ptr<Ciphertext<Element>>> ctexts, LPKeyPair<Element> keyPair){

	if(ctexts.size() < 2){
		return NULL;
	}

	int current_ctexts_length = ctexts.size();

	vector<shared_ptr<Ciphertext<Element>>> resultantCiphertexts;

	int count = 0;
	while(current_ctexts_length > 1){
		count++;
		cout << count << "THE OUPUT COUNTS " << endl;
		resultantCiphertexts = vector<shared_ptr<Ciphertext<Element>>>();

		if(ctexts.size()%2 != 0){ // carry one of the inputs through without multiply
			resultantCiphertexts.push_back(ctexts.at(ctexts.size() - 1));
		}
		for(unsigned int i = 0; i < ctexts.size() - 1; i += 2){


			vector<shared_ptr<Ciphertext<Element>>> ctextVectorResult1 = vector<shared_ptr<Ciphertext<Element>>>();
			ctextVectorResult1.push_back(ctexts.at(i));


			IntPlaintextEncoding ptValue1;
			cc->Decrypt(keyPair.secretKey, ctextVectorResult1, &ptValue1, true);



			vector<shared_ptr<Ciphertext<Element>>> ctextVectorResult2 = vector<shared_ptr<Ciphertext<Element>>>();
			ctextVectorResult2.push_back(ctexts.at(i + 1));


			IntPlaintextEncoding ptValue2;
			cc->Decrypt(keyPair.secretKey, ctextVectorResult2, &ptValue2, true);


			cout << "MULTIPLYING " << ptValue1.EvalToInt(1024) << " * " << ptValue2.EvalToInt(1024) << endl;


			resultantCiphertexts.push_back( cc->EvalMult(ctexts.at(i), ctexts.at(i + 1)));
		}	

		current_ctexts_length = resultantCiphertexts.size();
		ctexts = resultantCiphertexts;
	}

	return ctexts.at(0);
}


typedef Poly PolyType;

int main(int argc, char *argv[]) {





	LPKeyPair<PolyType> keyPair;

	vector<uint32_t> inputValues = {7,2,3,4,5};

	// vector<uint32_t> inputValues = {7,2,3,4};

	// vector<uint32_t> inputValues = {7,2,3,4};

	// vector<uint32_t> inputValues = {7,2};

	shared_ptr<CryptoContext<PolyType>> cryptoContext;

	vector<shared_ptr<Ciphertext<PolyType>>> encrpytedValues = vector<shared_ptr<Ciphertext<PolyType>>>();

	int plaintextModulus;

	try {

		plaintextModulus = 1024;

		int depth = 4;


		uint64_t cyclotomicOrder = 1024*2;


		/// SOLINAS PRIME
		// BigInteger modulusBigInt = PolyType::Integer("2147352577");
		// BigInteger rootOfUnityBigInt = PolyType::Integer("1539779042");


		BigInteger modulusBigInt = PolyType::Integer("2147473409");
		BigInteger rootOfUnityBigInt = PolyType::Integer("256290069");

		usint relinWindow = 1;
		float stDev = 10;

		MODE mode = RLWE;

		shared_ptr<typename PolyType::Params> parms;

		parms.reset( new typename PolyType::Params(cyclotomicOrder,
								modulusBigInt,
								rootOfUnityBigInt));

		cryptoContext = CryptoContextFactory<PolyType>::genCryptoContextSHIELD(
			parms, plaintextModulus, relinWindow, stDev, mode, depth);

		cryptoContext->Enable(ENCRYPTION);
		cryptoContext->Enable(SHE);



	} catch (const std::exception &e){
		std::cout << "Exception caught creating crypto context : " << e.what() << endl;
	}


	try{

		keyPair = cryptoContext->KeyGen();

		cryptoContext->EvalMultKeyGen(keyPair.secretKey);

		for (unsigned int i = 0; i < inputValues.size(); ++i)
		{

			std::vector<uint32_t> val = vector<uint32_t>();
			val.push_back(inputValues.at(i));

			IntPlaintextEncoding encodedValue = IntPlaintextEncoding(val);


			cout << "enc : " << i << endl;
			vector<shared_ptr<Ciphertext<PolyType>>> ciphertextValue = cryptoContext->Encrypt(keyPair.publicKey, encodedValue, true);
			cout << "enc done : " << i << endl;
			encrpytedValues.push_back(ciphertextValue[0]);
		}
	}  catch (const std::exception &e){
		std::cout << "Exception caught while encrypting " << e.what() << endl;
		
	}


	
	vector<int> allDecInts = vector<int>();

	for(unsigned int i = 0; i < encrpytedValues.size(); ++i){

		

		vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult1 = vector<shared_ptr<Ciphertext<PolyType>>>();
		ctextVectorResult1.push_back(encrpytedValues.at(i));


		IntPlaintextEncoding ptValue1;

		cout << endl << inputValues.at(i) << " as : " << endl;
		cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult1, &ptValue1, true);


		allDecInts.push_back(ptValue1.EvalToInt(1024));;


	}	

	cout << "Outside multiplying : ";
	for (unsigned int i = 0; i < allDecInts.size(); ++i)
	{
		if(i > 0){
			cout << " * ";
		}
		cout << allDecInts.at(i);
	}

	cout << endl;

	// shared_ptr<Ciphertext<PolyType>> multResult = runMultInTree(cryptoContext, encrpytedValues, keyPair);

	shared_ptr<Ciphertext<PolyType>> multResult = runMultInARow(cryptoContext, encrpytedValues);

	vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult = vector<shared_ptr<Ciphertext<PolyType>>>();
	ctextVectorResult.push_back(multResult);

	IntPlaintextEncoding ptValue;
	cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult, &ptValue, true);

	cout << "FINAL " << ptValue.EvalToInt(plaintextModulus) << endl;

	int expectedValue = inputValues.at(0);

	for (unsigned int i = 1; i < inputValues.size(); ++i)
	{
		expectedValue *= inputValues.at(i);
	}

	cout << "EXPECTED VALUE : " << expectedValue << endl;
}