/*
 * @file demo_she.cpp - PALISADE library.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @section DESCRIPTION
 * Demo software for FV multiparty operations.
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"
#include "encoding/byteplaintextencoding.h"
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







vector<uint32_t> convertIntToBits(uint32_t x) 
{
  vector<uint32_t> ret;
  int index = 32;
  while(x) {
    if (x&1)
      ret.push_back(1);
    else
      ret.push_back(0);
    x>>=1;  
    index--;
  }
  while(index > 0){
  	ret.push_back(0);
  	index--;
  }
  // reverse(ret.begin(),ret.end());
  return ret;
}



/* 

	returns a vector of ints that represent a modulus breakdown of the input
	the return vecotr is BIG-ENDIAN via reverse call at the end

	Returns big endian because this is what the encoding library expects

	ex: input: x = 10, modulus = 2 (the binary case)
		return: {1,0,1,0}


	input: x = 15, modulus = 2 (the binary case)
		return: {1, 1, 1, 1}

	input: x = 16, modulus = 2 (the binary case)
		return: {1, 0, 0, 0, 0}


	input: x = 15, modulus = 4
		return: {3, 3}

	input: x = 26, modulus = 4
		return: {1,2,2}

	input: x = 27, modulus = 4
		return: {1,2,3}

*/
int convertIntToModulo(int x, unsigned int modulus, vector<uint32_t>* returnVector) 
{
	if(modulus < 2){
		throw std::invalid_argument("modulus must be > 1");
	}
	if(modulus == 2){
		while(x > 0) {
			if (x&1)
				returnVector->push_back(1);
			else
				returnVector->push_back(0);
			x>>=1;
		}
	}
	else{
		while(x > 0) {
			returnVector->push_back(x%modulus);
			x = x/modulus;
		}
	}
	std::reverse(returnVector->begin(),returnVector->end());
	return 1;
}

vector<uint32_t>* convertIntToModulo(int x, unsigned int modulus) 
{
	vector<uint32_t>* returnVector = new vector<uint32_t>();
	if(modulus < 2){
		throw std::invalid_argument("modulus must be > 1");
	}
	if(modulus == 2){
		while(x > 0) {
			if (x&1)
				returnVector->push_back(1);
			else
				returnVector->push_back(0);
			x>>=1;
		}
	}
	else{
		while(x > 0) {
			returnVector->push_back(x%modulus);
			x = x/modulus;
		}
	}
	std::reverse(returnVector->begin(),returnVector->end());
	return returnVector;
}

uint32_t convertIntPlaintextEncodingToUintByModulo(IntPlaintextEncoding input, int modulus)
{
	uint32_t output = 0;

	for (unsigned int i = 0; i < input.size(); ++i)
	{
		if(input.at(i) > 0){
			output += input.at(i)^(i*modulus);
		}
	}
	return output;
}





int convertIntPlaintextEncodingToInt(IntPlaintextEncoding input)
{
	int output = 0;

	for (unsigned int i = 0; i < input.size(); ++i)
	{
		if(input.at(i) > 0){
			output += input.at(i) << i;
		}
	}
	return output;
}


uint32_t convertIntPlaintextEncodingToUint(IntPlaintextEncoding input)
{
	uint32_t output = 0;

	for (unsigned int i = 0; i < input.size(); ++i)
	{
		if(input.at(i) > 0){
			output += input.at(i) << i;
		}
	}
	return output;
}







template<class Element>
int runOperations(shared_ptr<CryptoContext<Element>> cryptoContext, int depth, int offset = 1, int isBitEncode = 0, int doMults = 1, vector<int> allValues = NULL)
{

	if(depth < 1){
		throw std::invalid_argument("Depth cannot be less than 1");
	}

	string operation; // for prints
	if(doMults == 1){
		operation = " X ";
	}
	else{
		operation = " + ";
	}

	if(allValues.size() < (unsigned int) depth + 1){
		// generate some values based on depth and offset
		std::vector<uint32_t> allValues;
		for (unsigned int i = 0; i < depth + 1 - allValues.size(); ++i)
		{
			allValues.push_back(i + offset);
		}
	}


	// int plaintextModulus =  cryptoContext->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);
	// cryptoContext->Enable(LEVELEDSHE);
	// cryptoContext->Enable(PRE);

	// key generation
	LPKeyPair<Element> keyPair = cryptoContext->KeyGen();

	// eval key generation
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	
	// saved ciphertext results (for mem totalling)
	vector<shared_ptr<Ciphertext<Element>>> savedCiphertextResults;


	vector<IntPlaintextEncoding> encodedValues;

	// encrypt all the values to be multiplied
	vector<vector<shared_ptr<Ciphertext<Element>>>> allCiphertexts;
	for (unsigned int i = 0; i < 2; ++i)
	{
		cout << "encrypting : " << allValues.at(i) << endl;

		cout << "AS : " << endl;
		cout << IntPlaintextEncoding(allValues.at(i)) << endl;
		if(isBitEncode == 1){
			encodedValues.push_back(IntPlaintextEncoding(convertIntToBits(allValues.at(i))));	
		}
		else{
			encodedValues.push_back(IntPlaintextEncoding(allValues.at(i)));
		}
		vector<shared_ptr<Ciphertext<Element>>> ciphertextValue = cryptoContext->Encrypt(keyPair.publicKey, encodedValues.at(i), true);
	
		allCiphertexts.push_back(ciphertextValue);


		// cout << "encrypted:" << endl;

		IntPlaintextEncoding ptValue;
		cryptoContext->Decrypt(keyPair.secretKey, ciphertextValue, &ptValue, true);
		// cout << "decrypted:" << endl;
		// cout << "Value :  " << allValues.at(i) << " decrypted to : " << convertIntPlaintextEncodingToInt(ptValue) << endl;

	}

	cout << "Doing an ADD " << endl;
	savedCiphertextResults.push_back(cryptoContext->EvalAdd(allCiphertexts.at(0)[0], allCiphertexts.at(1)[0]));

	IntPlaintextEncoding ptValueAdd;
	cryptoContext->Decrypt(keyPair.secretKey, vector<shared_ptr<Ciphertext<Element>>>(1, savedCiphertextResults.at(0)), &ptValueAdd, true);

	cout << "Value :  " << allValues.at(0) << " + " << allValues.at(1) << " decrypted to : \n";

	cout << convertIntPlaintextEncodingToInt(ptValueAdd) << endl << endl << endl;


	cout << "Doing a mult " << endl;
	savedCiphertextResults.push_back(cryptoContext->EvalMult(allCiphertexts.at(0)[0], allCiphertexts.at(1)[0]));

	IntPlaintextEncoding ptValueMult;
	cryptoContext->Decrypt(keyPair.secretKey, vector<shared_ptr<Ciphertext<Element>>>(1, savedCiphertextResults.at(1)), &ptValueMult, true);

	cout << "Value :  " << allValues.at(0) << " * " << allValues.at(1) << " decrypted to : \n";

	cout << convertIntPlaintextEncodingToInt(ptValueMult) << endl;

	exit(1);

	// // perform the add or mults
	// for (unsigned int i = 0; i < allCiphertexts.size() - 1; ++i) {

	// 	shared_ptr<Ciphertext<Element>> ciphertext1;
	// 	shared_ptr<Ciphertext<Element>> ciphertext2;
		
	// 	if(i == 0){
	// 		ciphertext1 = allCiphertexts.at(0)[0];
	// 		ciphertext2 = allCiphertexts.at(1)[0];
	// 	}
	// 	else{
	// 		ciphertext1 = savedCiphertextResults.at(i - 1);
	// 		ciphertext2 = allCiphertexts.at(i + 1)[0];
	// 	}
	// 	if(doMults == 1){
	// 		savedCiphertextResults.push_back(cryptoContext->EvalMult(ciphertext1,ciphertext2));
	// 	}
	// 	else{
	// 		savedCiphertextResults.push_back(cryptoContext->EvalAdd(ciphertext1,ciphertext2));
	// 	}
	// }










/*

	// decrypt the multiply values for sanity checking
	vector<IntPlaintextEncoding> plaintextMultipliersVector;
	for (unsigned int i = 0; i < allCiphertexts.size(); ++i)
	{	
		IntPlaintextEncoding ptValue;
		cryptoContext->Decrypt(keyPair.secretKey, allCiphertexts.at(i), &ptValue, true);
		plaintextMultipliersVector.push_back(ptValue);

		// cout << "Value :  " << allValues.at(i) << " decrypted to : " << convertIntPlaintextEncodingToInt(ptValue) << endl;


	}

*/















	// // decrypt each result ciphertext
	// vector<IntPlaintextEncoding> plaintextResultsVector;
	// for (unsigned int i = 0; i < savedCiphertextResults.size(); ++i)
	// {	
	// 	IntPlaintextEncoding newPtValue;
	// 	cryptoContext->Decrypt(keyPair.secretKey, vector<shared_ptr<Ciphertext<Element>>>(1, savedCiphertextResults.at(i)), &newPtValue, true);
	// 	plaintextResultsVector.push_back(newPtValue);
	// }
	

	// int ptval1;
	// int ptval2;
	// int ptresult;

	// int currentExpectedResult = -1;
	// for (unsigned int i = 0; i < allValues.size() - 1; ++i)
	// {
	// 	if(i == 0) {
	// 		ptval1 = convertIntPlaintextEncodingToInt(plaintextMultipliersVector.at(0));
	// 		ptval2 = convertIntPlaintextEncodingToInt(plaintextMultipliersVector.at(1));
	// 		ptresult = convertIntPlaintextEncodingToInt(plaintextResultsVector.at(0));

	// 		if(doMults == 1){
	// 			currentExpectedResult = allValues.at(0) * allValues.at(1);
	// 		} 
	// 		else{
	// 			currentExpectedResult = allValues.at(0) * allValues.at(1);
	// 		}
	// 		cout << "Expected result : " << allValues.at(0) << operation << allValues.at(1) << " = " <<  currentExpectedResult << endl;
	// 	}
	// 	else{
	// 		ptval1 = convertIntPlaintextEncodingToInt(plaintextResultsVector.at(i - 1));
	// 		ptval2 = convertIntPlaintextEncodingToInt(plaintextMultipliersVector.at(i+1));
	// 		ptresult = convertIntPlaintextEncodingToInt(plaintextResultsVector.at(i));

	// 		cout << "Expected result : " << currentExpectedResult << operation << allValues.at(i + 1) << " = ";

	// 		if(doMults == 1){
	// 			currentExpectedResult *= allValues.at(i + 1);
	// 		} 
	// 		else{
	// 			currentExpectedResult += allValues.at(i + 1);
	// 		}
	// 		cout << currentExpectedResult << endl;
	// 	}
		
	// 	cout << "Got             : " << ptval1 << operation << ptval2 << " = " << ptresult << endl << endl;
	// }

	return 1;

}




// typedef DCRTPoly PolyType;
typedef Poly PolyType;


int main(int argc, char *argv[]) {


	// vector<int> intputVectorOfIntsToMultiply = {7,2,3,4,5,6};


	vector<int> intputVectorOfIntsToMultiply = {7,0,3,4,5,6,6,4,32,2};

	int depth = 4;

	int offset = 6;

	int plaintextModulus = 1024;

	int isBitEncode = 0;

	int doMults = 1;

	/*
		Best for bv so far: depth 3, offset 7, pt mod 4
	*/

	shared_ptr<CryptoContext<PolyType>> cryptoContext;

	double startTime = currentDateTime();

	string schemeLabel = "SHIELD";
	

	cout << "Gen crypto context " << schemeLabel <<endl;
	try{


		uint64_t cyclotomicOrder = 1024*2;  // cyclotomic order!!! ring dimension = cyclotomicOrder/ 2
		// uint64_t cyclotomicOrder = 128*4;  // cyclotomic order!!! ring dimension = cyclotomicOrder/ 2
// 4294946818
// 4294967296		
// 4294967295
													  
// 2147352577

//2147352577
// 2147352577
// 461230749		
		// BigInteger modulusBigInt = PolyType::Integer("268441601");
		// BigInteger rootOfUnityBigInt = PolyType::Integer("16947867");

		// 0x7FFE001
		// 1111 1111 1111 1100 0000 0000 001
 		// 0111 1111 1111 1110 0000 0000 0001

													  // 134209537
		// BigInteger modulusBigInt = PolyType::Integer("2147473409");
		// BigInteger rootOfUnityBigInt = PolyType::Integer("256290069");


		BigInteger modulusBigInt = PolyType::Integer("2147352577");
		BigInteger rootOfUnityBigInt = PolyType::Integer("461230749");

		// BigInteger modulusBigInt = PolyType::Integer("1073750017");
		// BigInteger rootOfUnityBigInt = PolyType::Integer("180790047");

		usint relinWindow = 1;
		float stDev = 10;

		MODE mode = RLWE;

		shared_ptr<typename PolyType::Params> parms;

		parms.reset( new typename PolyType::Params(cyclotomicOrder,
								modulusBigInt,
								rootOfUnityBigInt));


		cout << "Gen crypto context SHIELD" << endl;
		cryptoContext = CryptoContextFactory<PolyType>::genCryptoContextSHIELD(
			parms, plaintextModulus, relinWindow, stDev, mode, depth);
		
		cout << "running for " << schemeLabel << " and depth " << depth << endl;

		std::cout << "plaintext modulus = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
		std::cout << "CyclotomicOrder/2 = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
		std::cout << "Modulus = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus() << std::endl;	
		std::cout << "root of unity = " << cryptoContext->GetRootOfUnity() << std::endl;
	
		
		runOperations<PolyType>(cryptoContext, depth, offset, isBitEncode, doMults, intputVectorOfIntsToMultiply);

	} catch (const std::exception &e){
		std::cout << "Exception caught " << e.what() << endl;
		
	}

	cout << "Completed with total time " << currentDateTime() - startTime << endl;

		
		// float securityLevel = 1.006;

	cout << "total time for gen " << schemeLabel << " with depth " << depth << " is :: " << currentDateTime() - startTime << endl;

	return 0;
}
