
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
shared_ptr<Ciphertext<Element>> runAddInTree(shared_ptr<CryptoContext<Element>> cc, vector<shared_ptr<Ciphertext<Element>>> ctexts, LPKeyPair<Element> keyPair){

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


			resultantCiphertexts.push_back( cc->EvalAdd(ctexts.at(i), ctexts.at(i + 1)));
		}	

		current_ctexts_length = resultantCiphertexts.size();
		ctexts = resultantCiphertexts;
	}

	return ctexts.at(0);
}





template<class Element>
shared_ptr<Ciphertext<Element>> runMultInARow(shared_ptr<CryptoContext<Element>> cc, vector<shared_ptr<Ciphertext<Element>>> ctexts){
	if(ctexts.size() < 2){
		return NULL;
	}

	cout << "Running mult in a row" << endl;

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


			// IntPlaintextEncoding ptValue1;
			// cc->Decrypt(keyPair.secretKey, ctextVectorResult1, &ptValue1, true);



			vector<shared_ptr<Ciphertext<Element>>> ctextVectorResult2 = vector<shared_ptr<Ciphertext<Element>>>();
			ctextVectorResult2.push_back(ctexts.at(i + 1));


			// IntPlaintextEncoding ptValue2;
			// cc->Decrypt(keyPair.secretKey, ctextVectorResult2, &ptValue2, true);


			// cout << "MULTIPLYING " << ptValue1.EvalToInt(1024) << " * " << ptValue2.EvalToInt(1024) << endl;


			resultantCiphertexts.push_back( cc->EvalMult(ctexts.at(i), ctexts.at(i + 1)));
		}	

		current_ctexts_length = resultantCiphertexts.size();
		ctexts = resultantCiphertexts;
	}

	return ctexts.at(0);
}


typedef Poly PolyType;




int main(int argc, char *argv[]) {



	// BigInteger firstPrime = lbcrypto::FirstPrime<BigInteger>(301, 16384);

	// BigInteger rootOfU = lbcrypto::RootOfUnity<BigInteger>(16384, firstPrime);

	// cout << "FIRST PRIME "  << firstPrime << endl;


	// cout << "ROOT OF UNITY " <<  rootOfU << endl;
		
	// exit(1);

	LPKeyPair<PolyType> keyPair;

	// vector<uint32_t> inputValues = {1,1,1,1,1,1};

	// vector<uint32_t> inputValues = {2,2,1,2,3,2,2,3};

	// vector<uint32_t> inputValues = {1,2,3,4,5,6};

	vector<uint32_t> inputValues = {6,2,1,3,5,7};

	// vector<uint32_t> inputValues = {7,2,3,4};

	// vector<uint32_t> inputValues = {7,2,3,4};

	// vector<uint32_t> inputValues = {2,4,5};

	// vector<uint32_t> inputValues = {2,3};

	shared_ptr<CryptoContext<PolyType>> cryptoContext;

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

			cryptoContext = CryptoContextFactory<PolyType>::genCryptoContextSHIELD(
				parms, plaintextModulus, relinWindow, stDev, mode, depth);

			cryptoContext->Enable(ENCRYPTION);
			cryptoContext->Enable(SHE);
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


		keyPair = cryptoContext->KeyGen();

		cryptoContext->EvalMultKeyGen(keyPair.secretKey);


		std::vector<uint32_t> zeroVal = vector<uint32_t>();
		zeroVal.push_back(0);
		IntPlaintextEncoding encodedZeroValue = IntPlaintextEncoding(zeroVal);
		vector<shared_ptr<Ciphertext<PolyType>>> ciphertextZeroValue = cryptoContext->Encrypt(keyPair.publicKey, encodedZeroValue, true);

		std::vector<uint32_t> oneVal = vector<uint32_t>();
		oneVal.push_back(1);
		IntPlaintextEncoding encodedOneValue = IntPlaintextEncoding(oneVal);
		vector<shared_ptr<Ciphertext<PolyType>>> ciphertextOneValue = cryptoContext->Encrypt(keyPair.publicKey, encodedOneValue, true);

		


		vector<shared_ptr<Ciphertext<PolyType>>> currentCiphertextValueVec = cryptoContext->Encrypt(keyPair.publicKey, encodedZeroValue, true);


		shared_ptr<Ciphertext<PolyType>> currentCiphertextValue = currentCiphertextValueVec.at(0);

		for (unsigned int i = 0; i < inputValues.size(); ++i)
		{

			std::vector<uint32_t> val = vector<uint32_t>();
			// val.push_back(1);
			val.push_back(inputValues.at(i));

			IntPlaintextEncoding encodedValue = IntPlaintextEncoding(val);

			// IntPlaintextEncoding encodedValue = IntPlaintextEncoding(inputValues.at(i));

			cout << "enc : " << inputValues.at(i) << " encoded as : " << endl << endl;
			cout << encodedValue << endl << endl;
			vector<shared_ptr<Ciphertext<PolyType>>> ciphertextValue = cryptoContext->Encrypt(keyPair.publicKey, encodedValue, true);
			encrpytedValues.push_back(ciphertextValue[0]);

			if(i == 1){
				cout << " include : " << inputValues.at(i) << endl;
				currentCiphertextValue = cryptoContext->EvalAdd(currentCiphertextValue, cryptoContext->EvalMult(ciphertextValue.at(0), ciphertextOneValue.at(0)));	
			}
			else{
				cout << " do not include : " << inputValues.at(i) << endl;
				currentCiphertextValue = cryptoContext->EvalAdd(currentCiphertextValue, cryptoContext->EvalMult(ciphertextValue.at(0), ciphertextZeroValue.at(0)));	
			}
			

			


		}


		vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult1 = vector<shared_ptr<Ciphertext<PolyType>>>();
		ctextVectorResult1.push_back(currentCiphertextValue);

		IntPlaintextEncoding ptValue1;
		cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult1, &ptValue1, true);

		exit(1);

	}  catch (const std::exception &e){
		std::cout << "Exception caught while encrypting " << e.what() << endl;
		
	}


	
	vector<int> allDecInts = vector<int>();

	for(unsigned int i = 0; i < encrpytedValues.size(); ++i){

		

		vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult1 = vector<shared_ptr<Ciphertext<PolyType>>>();
		ctextVectorResult1.push_back(encrpytedValues.at(i));


		IntPlaintextEncoding ptValue1;

		cout << endl << endl << endl << inputValues.at(i) << " as : " << endl;
		cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult1, &ptValue1, true);
		cout << "EVAL TO INT : " << ptValue1.EvalToInt(1024) << endl;

		allDecInts.push_back(ptValue1.EvalToInt(1024));;


	}	

	cout << endl << "Outside multiplying : ";
	for (unsigned int i = 0; i < allDecInts.size(); ++i)
	{
		if(i > 0){
			cout << " * ";
		}
		cout << allDecInts.at(i);
	}

	cout << endl;


	// cout << " MULTIPLYING " << inputValues.at(0) << " * " << inputValues.at(1) << endl << endl;

	// vector<shared_ptr<Ciphertext<PolyType>>> mult11Values = vector<shared_ptr<Ciphertext<PolyType>>>();
	// mult11Values.push_back(encrpytedValues.at(0));
	// mult11Values.push_back(encrpytedValues.at(1));

	// shared_ptr<Ciphertext<PolyType>> multResult11 = runMultInARow(cryptoContext, mult11Values);

	// uint32_t currentMultResult =  inputValues.at(0) * inputValues.at(1);

	// cout << "expected : " << currentMultResult << endl;

	// cout << "GOT  >>> " << endl;

	// IntPlaintextEncoding ptValue11;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult11 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult11.push_back(multResult11);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult11, &ptValue11, true);

	// cout << " GOT ^^ " << endl << endl;




	// cout << " MULTIPLYING " << inputValues.at(2) << " * " << inputValues.at(3) << endl << endl;

	// vector<shared_ptr<Ciphertext<PolyType>>> mult22Values = vector<shared_ptr<Ciphertext<PolyType>>>();
	// mult22Values.push_back(encrpytedValues.at(2));
	// mult22Values.push_back(encrpytedValues.at(3));
	
	// shared_ptr<Ciphertext<PolyType>> multResult22 = runMultInARow(cryptoContext, mult22Values);


	// uint32_t currentMultResult22 =  inputValues.at(2) * inputValues.at(3);

	// cout << "expected : " << currentMultResult22 << endl;

	// cout << "GOT  >>> " << endl;

	// IntPlaintextEncoding ptValue22;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult22 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult22.push_back(multResult22);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult22, &ptValue22, true);

	// cout << " GOT ^^ " << endl << endl;





	// cout << " MULTIPLYING " << inputValues.at(4) << " * " << inputValues.at(5) << endl << endl;

	// vector<shared_ptr<Ciphertext<PolyType>>> mult44Values = vector<shared_ptr<Ciphertext<PolyType>>>();
	// mult44Values.push_back(encrpytedValues.at(4));
	// mult44Values.push_back(encrpytedValues.at(5));
	
	// shared_ptr<Ciphertext<PolyType>> multResult44 = runMultInARow(cryptoContext, mult44Values);


	// uint32_t currentMultResult44 =  inputValues.at(4) * inputValues.at(5);

	// cout << "expected : " << currentMultResult44 << endl;

	// cout << "GOT  >>> " << endl;

	// IntPlaintextEncoding ptValue44;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult44 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult44.push_back(multResult44);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult44, &ptValue44, true);

	// cout << " GOT ^^ " << endl << endl;
	











	// cout << "MULTIPLYING THE RESULTS!!" << currentMultResult << " * " << currentMultResult22 << " = " << currentMultResult * currentMultResult22 << endl;
	
	// vector<shared_ptr<Ciphertext<PolyType>>> mult33Values = vector<shared_ptr<Ciphertext<PolyType>>>();

	// mult33Values.push_back(multResult11);
	// mult33Values.push_back(multResult22);


	// uint32_t currentMultResult33 = currentMultResult * currentMultResult22;

	// shared_ptr<Ciphertext<PolyType>> multResult33 = runMultInARow(cryptoContext, mult33Values);


	// cout << "EXPECT " << currentMultResult << " * " << currentMultResult22 << " = " << currentMultResult33 << endl;
	// cout << " GOT >>>" << endl << endl;

	// IntPlaintextEncoding ptValue33;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult33 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult33.push_back(multResult33);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult33, &ptValue33, true);







	// cout << "MULTIPLYING THE RESULTS!!" << currentMultResult33 << " * " << currentMultResult44 << " = " << currentMultResult33 * currentMultResult44 << endl;
	
	// uint32_t currentMultResult55 = currentMultResult33 * currentMultResult44;


	// vector<shared_ptr<Ciphertext<PolyType>>> mult55Values = vector<shared_ptr<Ciphertext<PolyType>>>();

	// mult55Values.push_back(multResult33);
	// mult55Values.push_back(multResult44);


	// shared_ptr<Ciphertext<PolyType>> multResult55 = runMultInARow(cryptoContext, mult55Values);


	// cout << "EXPECT " << currentMultResult33 << " * " << currentMultResult44 << " = " << currentMultResult55 << endl;
	// cout << " GOT >>>" << endl << endl;

	// IntPlaintextEncoding ptValue55;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult55 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult55.push_back(multResult55);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult55, &ptValue55, true);


























//////////////////////////////////////////// 
	///////////////////
	//////////////////
	// ADDS
	//
	//


	// cout << " Adding " << inputValues.at(0) << " + " << inputValues.at(1) << endl << endl;

	// vector<shared_ptr<Ciphertext<PolyType>>> mult11Values = vector<shared_ptr<Ciphertext<PolyType>>>();
	// mult11Values.push_back(encrpytedValues.at(0));
	// mult11Values.push_back(encrpytedValues.at(1));

	// shared_ptr<Ciphertext<PolyType>> multResult11 = runAddInARow(cryptoContext, mult11Values);

	// uint32_t currentMultResult =  inputValues.at(0) + inputValues.at(1);

	// cout << "expected : " << currentMultResult << endl;

	// cout << "GOT  >>> " << endl;

	// IntPlaintextEncoding ptValue11;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult11 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult11.push_back(multResult11);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult11, &ptValue11, true);

	// cout << " GOT ^^ " << endl << endl;




	// cout << " Adding " << inputValues.at(2) << " + " << inputValues.at(3) << endl << endl;

	// vector<shared_ptr<Ciphertext<PolyType>>> mult22Values = vector<shared_ptr<Ciphertext<PolyType>>>();
	// mult22Values.push_back(encrpytedValues.at(2));
	// mult22Values.push_back(encrpytedValues.at(3));
	
	// shared_ptr<Ciphertext<PolyType>> multResult22 = runAddInARow(cryptoContext, mult22Values);


	// uint32_t currentMultResult22 =  inputValues.at(2) + inputValues.at(3);

	// cout << "expected : " << currentMultResult22 << endl;

	// cout << "GOT  >>> " << endl;

	// IntPlaintextEncoding ptValue22;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult22 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult22.push_back(multResult22);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult22, &ptValue22, true);

	// cout << " GOT ^^ " << endl << endl;





	// cout << " Adding " << inputValues.at(4) << " + " << inputValues.at(5) << endl << endl;

	// vector<shared_ptr<Ciphertext<PolyType>>> mult44Values = vector<shared_ptr<Ciphertext<PolyType>>>();
	// mult44Values.push_back(encrpytedValues.at(4));
	// mult44Values.push_back(encrpytedValues.at(5));
	
	// shared_ptr<Ciphertext<PolyType>> multResult44 = runAddInARow(cryptoContext, mult44Values);


	// uint32_t currentMultResult44 =  inputValues.at(4) + inputValues.at(5);

	// cout << "expected : " << currentMultResult44 << endl;

	// cout << "GOT  >>> " << endl;

	// IntPlaintextEncoding ptValue44;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult44 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult44.push_back(multResult44);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult44, &ptValue44, true);

	// cout << " GOT ^^ " << endl << endl;
	











	// cout << "Adding THE RESULTS!!" << currentMultResult << " + " << currentMultResult22 << " = " << currentMultResult + currentMultResult22 << endl;
	
	// vector<shared_ptr<Ciphertext<PolyType>>> mult33Values = vector<shared_ptr<Ciphertext<PolyType>>>();

	// mult33Values.push_back(multResult11);
	// mult33Values.push_back(multResult22);


	// uint32_t currentMultResult33 = currentMultResult + currentMultResult22;

	// shared_ptr<Ciphertext<PolyType>> multResult33 = runAddInARow(cryptoContext, mult33Values);


	// cout << "EXPECT " << currentMultResult << " + " << currentMultResult22 << " = " << currentMultResult33 << endl;
	// cout << " GOT >>>" << endl << endl;

	// IntPlaintextEncoding ptValue33;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult33 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult33.push_back(multResult33);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult33, &ptValue33, true);







	// cout << "Adding THE RESULTS!!" << currentMultResult33 << " + " << currentMultResult44 << " = " << currentMultResult33 + currentMultResult44 << endl;
	
	// uint32_t currentMultResult55 = currentMultResult33 * currentMultResult44;


	// vector<shared_ptr<Ciphertext<PolyType>>> mult55Values = vector<shared_ptr<Ciphertext<PolyType>>>();

	// mult55Values.push_back(multResult33);
	// mult55Values.push_back(multResult44);


	// shared_ptr<Ciphertext<PolyType>> multResult55 = runAddInARow(cryptoContext, mult55Values);


	// cout << "EXPECT " << currentMultResult33 << " + " << currentMultResult44 << " = " << currentMultResult55 << endl;
	// cout << " GOT >>>" << endl << endl;

	// IntPlaintextEncoding ptValue55;

	// vector<shared_ptr<Ciphertext<PolyType>>> ctextVectorResult55 = vector<shared_ptr<Ciphertext<PolyType>>>();
	// ctextVectorResult55.push_back(multResult55);

	// cryptoContext->Decrypt(keyPair.secretKey, ctextVectorResult55, &ptValue55, true);




















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