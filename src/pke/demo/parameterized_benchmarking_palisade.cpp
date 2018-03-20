


// # to compile src/pke/bin/demo/parameterized_benchmarking_palisade.cpp for testing shield

// 	g++ -std=gnu++11 -fPIC -g -Wall -Werror -O3 -fopenmp -pthread -I src/core/lib -I src/pke/lib -I src/trapdoor/lib -I src/circuit/lib -I test -I third-party/include -I third-party/include -c -o src/pke/bin/demo/parameterized_benchmarking_palisade.o src/pke/demo/parameterized_benchmarking_palisade.cpp

// 	g++ -std=gnu++11 -fPIC -o bin/demo/pke/parameterized_benchmarking_palisade src/pke/bin/demo/parameterized_benchmarking_palisade.o bin/lib/libPALISADEpke.so bin/lib/libPALISADEcore.so -Lbin/lib   -pthread -fopenmp   -lgomp

// 	./bin/demo/pke/parameterized_benchmarking_palisade











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




// flow : 
// 	get cc from input

// 	extract q, n, sigma from cc

// 	run mult

// 	print results and put in csv



template<class Element>
shared_ptr<Ciphertext<Element>> runAddInARow(shared_ptr<CryptoContext<Element>> cc, vector<shared_ptr<Ciphertext<Element>>> ctexts){
	if(ctexts.size() < 2){
		return NULL;
	}
	shared_ptr<Ciphertext<Element>> currentCtext = ctexts.at(0);
	for(unsigned int i = 1; i < ctexts.size(); i++){
		currentCtext = cc->EvalAdd(currentCtext, ctexts.at(i));
	}

	return currentCtext;
}






template<class Element>
shared_ptr<Ciphertext<Element>> runMultInARow(shared_ptr<CryptoContext<Element>> cc, vector<shared_ptr<Ciphertext<Element>>> ctexts){
	if(ctexts.size() < 2){
		return NULL;
	}

	// cout << "Running mult in a row" << endl;

	shared_ptr<Ciphertext<Element>> currentCtext = ctexts.at(0);
	for(unsigned int i = 1; i < ctexts.size(); i++){
		currentCtext = cc->EvalMult(currentCtext, ctexts.at(i));
	}

	return currentCtext;
}



typedef Poly PolyType;




int testall(string schemeLabel) {


	LPKeyPair<PolyType> keyPair;


	vector<uint32_t> inputValues = {1,1};


	shared_ptr<CryptoContext<PolyType>> cryptoContext;

	vector<shared_ptr<Ciphertext<PolyType>>> encrpytedValues = vector<shared_ptr<Ciphertext<PolyType>>>();

	int plaintextModulus;


	


	try {

		if(false){
			plaintextModulus = 1024;

			int depth = 4;


			uint64_t cyclotomicOrder = 1024*2;


			/// SOLINAS PRIME
			BigInteger modulusBigInt = PolyType::Integer("2147352577");
			BigInteger rootOfUnityBigInt = PolyType::Integer("1539779042");



			usint relinWindow = 1;
			float stDev = 10;

			MODE mode = RLWE;

			shared_ptr<typename PolyType::Params> parms;

			parms.reset( new typename PolyType::Params(cyclotomicOrder,
									modulusBigInt,
									rootOfUnityBigInt));

			cryptoContext = CryptoContextFactory<PolyType>::genCryptoContextSHIELD(
				parms, plaintextModulus, relinWindow, stDev, mode, depth);

			
		}
		else {
			

			// schemeLabel = allSchemes.at(1);
			cryptoContext = CryptoContextHelper::getNewContext(schemeLabel);

		}



	} catch (const std::exception &e){
		std::cout << "Exception caught creating crypto context : " << e.what() << endl;
	}

	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	try{

		keyPair = cryptoContext->KeyGen();

		cryptoContext->EvalMultKeyGen(keyPair.secretKey);

		for (unsigned int i = 0; i < inputValues.size(); ++i)
		{

			std::vector<uint32_t> val = vector<uint32_t>();
			// val.push_back(1);
			val.push_back(inputValues.at(i));

			IntPlaintextEncoding encodedValue = IntPlaintextEncoding(val);

			// IntPlaintextEncoding encodedValue = IntPlaintextEncoding(inputValues.at(i));

			// cout << "enc : " << inputValues.at(i) << " encoded as : " << endl << endl;
			// cout << encodedValue << endl << endl;
			vector<shared_ptr<Ciphertext<PolyType>>> ciphertextValue = cryptoContext->Encrypt(keyPair.publicKey, encodedValue, true);
			encrpytedValues.push_back(ciphertextValue[0]);
		}
	}  catch (const std::exception &e){
		std::cout << "Exception caught while encrypting " << e.what() << endl;
		
	}


	
	// vector<int> allDecInts = vector<int>();

	// for(unsigned int i = 0; i < encrpytedValues.size(); ++i){

		

	// 	vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult1 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// 	ctextVectorResult1.push_back(encrpytedValues.at(i));


	// 	IntPlaintextEncoding ptValue1;

	// 	cout << endl << endl << endl << inputValues.at(i) << " as : " << endl;
	// 	cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult1, &ptValue1, true);
	// 	cout << "EVAL TO INT : " << ptValue1.EvalToInt(1024) << endl;

	// 	allDecInts.push_back(ptValue1.EvalToInt(1024));;


	// }	

	// cout << endl << "Outside multiplying : ";
	// for (unsigned int i = 0; i < allDecInts.size(); ++i)
	// {
	// 	if(i > 0){
	// 		cout << " * ";
	// 	}
	// 	cout << allDecInts.at(i);
	// }

	// cout << endl;





// THIS IS WHERE IT RUNS ALL THE MULTS
	double muldiff, mulstart, mulfinish;

	mulstart = currentDateTime();

	shared_ptr<Ciphertext<PolyType>> multResult = runMultInARow(cryptoContext, encrpytedValues);

	mulfinish = currentDateTime();

	muldiff = mulfinish - mulstart;



// THIS IS WHERE IT RUNS ALL THE ADDS
	double adddiff, addstart, addfinish;

	addstart = currentDateTime();

	shared_ptr<Ciphertext<PolyType>> addResult = runAddInARow(cryptoContext, encrpytedValues);

	addfinish = currentDateTime();

	adddiff = addfinish - addstart;

		
	const BigInteger q =  cryptoContext->GetModulus();

	const BigInteger n =  cryptoContext->GetCyclotomicOrder()/2;


	// if(!std::is_same<LPCryptoParametersRLWE, cryptoContext->GetCryptoParameters()>::value){
	// 	cout << "IS NOT RIGHT TEMPLATE OH NOES!" << endl;
	// 	exit(1);
	// }


	const shared_ptr<LPCryptoParametersRLWE<PolyType>> cryptoParams =
		std::dynamic_pointer_cast<LPCryptoParametersRLWE<PolyType>>(cryptoContext->GetCryptoParameters());


	// LPCryptoParametersRLWE
	// if((LPCryptoParametersRLWE) cryptoContext->GetCryptoParameters())->GetMode() == RLWE){
		float sigma =  cryptoParams->GetDistributionParameter();
		cout << "ADD TIME : " << adddiff << "  Mult time : " << muldiff << " q : " << q << " n : " << n << " sigma: " << sigma <<" scheme  : " << schemeLabel << endl; 

	// }
	

	return 1;


	// cout << "ADD TIME : " << adddiff << "  Mult time : " << muldiff << " q : " << q << " n : " << n << " scheme  : " << schemeLabel; 




	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult.push_back(multResult);

	// IntPlaintextEncoding ptValue;
	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult, &ptValue, true);

	// cout << "FINAL " << ptValue.EvalToInt(plaintextModulus) << endl;

	// int expectedValue = inputValues.at(0);

	// for (unsigned int i = 1; i < inputValues.size(); ++i)
	// {
	// 	expectedValue *= inputValues.at(i);
	// }

	// cout << "EXPECTED VALUE : " << expectedValue << endl;
}





int main(int argc, char *argv[]){
	std::vector<string> allSchemes = {
		"BV-PRE", 
		"BV1", 
		"BV2", 
		"BV3", 
		"BV4", 
		"BV5", 
		"FV-PRE", 
		"FV1", 
		"FV2", 
		// "LTV-PRE", 
		// "LTV1", 
		// "LTV2", 
		// "LTV3", 
		// "LTV4", 
		// "LTV5", 
		// "Null", 
		// "Null-PRE", 
		// "Null2", 
		// "StSt-PRE", 
		// "StSt1", 
		// "StSt2", 
		// "StSt3", 
		// "StSt4", 
		// "StSt5", 
		// "StSt6"
	};
	for (unsigned int i = 0; i < allSchemes.size(); ++i)
	{
		testall(allSchemes.at(i));
	}
}