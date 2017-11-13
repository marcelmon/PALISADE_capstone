/*
 * @file demo_pke.cpp - PALISADE library.
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
#include <sstream>
#include <math.h>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"
#include "encoding/byteplaintextencoding.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;


std::vector<tuple<BytePlaintextEncoding,IntPlaintextEncoding>> getEncodedPlaintextFromCSV(std::string csvData)
{

	std::vector<tuple<BytePlaintextEncoding,IntPlaintextEncoding>> encodedPlaintext;

	std::istringstream ss(csvData);
	std::string line;

	std::string name;
	std::string value;
	
	// int vectorSize = 0;

	// break input on newline
	while(std::getline(ss, line)) {

		std::istringstream line_ss(line);
		std::getline(line_ss, name, ',');
		BytePlaintextEncoding namePlaintext(name);

		std::getline(line_ss, value);
		std::istringstream to_uint_reader(value);
		uint32_t uint_val;
		to_uint_reader >> uint_val;
		IntPlaintextEncoding valuesPlaintext(uint_val);

		encodedPlaintext.push_back(tuple<BytePlaintextEncoding, IntPlaintextEncoding>(namePlaintext, valuesPlaintext));
	}

	return encodedPlaintext;
}

int main(int argc, char *argv[]) {

	

	// StSt6 uses plaintext modulus of 256
	string input = "FV2";

	shared_ptr<CryptoContext<Poly>> cryptoContext = CryptoContextHelper::getNewContext(input);
	if( !cryptoContext ) {
		cout << "Error on " << input << endl;
		return 0;
	}

	std::cout << "Created using "<< input << endl;


	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(PRE);
	cryptoContext->Enable(SHE);


	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	std::cout << endl;


	string namesAndValues = "AlanBo,3\nJeffBoboboTAA,1\nEmilyBoboboWOO,3\nBinkyBomber,5\n";

	std::vector<tuple<BytePlaintextEncoding,IntPlaintextEncoding>> newEncodedPlaintext = getEncodedPlaintextFromCSV(namesAndValues);

	uint32_t modulusVal = (uint32_t) cryptoContext->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	// print for sanity check
	for (unsigned int i = 0; i < newEncodedPlaintext.size(); ++i) {

		std::cout << "new Names plaintext : " << get<0>(newEncodedPlaintext.at(i)) << endl;
		std::cout << "new Values vector plaintext : " << get<1>(newEncodedPlaintext.at(i)) << endl;
		std::cout << "new Values Int Value plaintext : " << get<1>(newEncodedPlaintext.at(i)).EvalToInt(modulusVal) << endl;
	}
	std::cout << endl;





	LPKeyPair<Poly> keyPair;
	keyPair = cryptoContext->KeyGen();
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	// stores vector of tuples <name ciphertext, value ciphertext>
	std::vector<  tuple<std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>> > > 	csvCiphertext;


	// encrypt the data and store in vector of tuples
	for (unsigned int i = 0; i < newEncodedPlaintext.size(); ++i) {

		std::vector<shared_ptr<Ciphertext<Poly>>> nameCiphertext = cryptoContext->Encrypt(keyPair.publicKey, get<0>(newEncodedPlaintext.at(i)), true);

		std::vector<shared_ptr<Ciphertext<Poly>>> valueCiphertext = cryptoContext->Encrypt(keyPair.publicKey, get<1>(newEncodedPlaintext.at(i)), true);

		csvCiphertext.push_back(std::tuple<std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>> >(nameCiphertext, valueCiphertext));

	}


	// print for sanity check
	for (unsigned int i = 0; i < csvCiphertext.size(); ++i)
	{
		std::cout << "Name ciphertext : " << get<0>(csvCiphertext.at(i))[0] << endl;

		std::cout << "Value ciphertext : " << get<1>(csvCiphertext.at(i))[0] << endl;

		std::cout << endl;
	}



	std::vector<BytePlaintextEncoding> namePlaintextDecVector;
	std::vector<IntPlaintextEncoding> valuePlaintextDecVector;

	// decrypt and print for sanity check
	for (unsigned int i = 0; i < csvCiphertext.size(); ++i) {

		BytePlaintextEncoding namePlaintextDec;
		cryptoContext->Decrypt(keyPair.secretKey, get<0>(csvCiphertext.at(i)), &namePlaintextDec, true);
		namePlaintextDec.resize(get<0>(newEncodedPlaintext.at(i)).size());

		std::cout << "Name plaintext decrypted : " << namePlaintextDec << endl;


		IntPlaintextEncoding valuePlaintextDec;
		cryptoContext->Decrypt(keyPair.secretKey, get<1>(csvCiphertext.at(i)), &valuePlaintextDec, true);
		valuePlaintextDec.resize(get<0>(newEncodedPlaintext.at(i)).size());

		std::cout << "Value vector plaintext decrypted : " << valuePlaintextDec << endl;

		std::cout << "Value Int Val plaintext decrypted : " << valuePlaintextDec.EvalToInt(modulusVal) << endl;

		std::cout << endl;
	}

	// uint32_t doAdd 		= 0;
	// uint32_t doSub 		= 1;
	// uint32_t doMult		= 2;

	// a query is a tuple <seach term, operation (as uint), operation value (as int)>
	std::vector<tuple<string, uint32_t, int>> queries;

	queries.push_back(tuple<string, uint32_t, int>("Bo", 0, 0));
	queries.push_back(tuple<string, uint32_t, int>("AlanBo", 2, 25));
	queries.push_back(tuple<string, uint32_t, int>("JeffBoboboTBA", 0, 5));
	queries.push_back(tuple<string, uint32_t, int>("JeffBoboboTAA", 1, 2));
	queries.push_back(tuple<string, uint32_t, int>("BinkyBomber", 0, 16));


	std::vector<tuple<BytePlaintextEncoding, IntPlaintextEncoding, IntPlaintextEncoding>> encodedPlaintextQueries;

	for (unsigned int i = 0; i < queries.size(); ++i)
	{
		BytePlaintextEncoding searchTerm(get<0>(queries.at(i)));
		IntPlaintextEncoding queryOperation(get<1>(queries.at(i)));
		IntPlaintextEncoding operationValue(get<2>(queries.at(i)));

		encodedPlaintextQueries.push_back(tuple<BytePlaintextEncoding, IntPlaintextEncoding, IntPlaintextEncoding>(searchTerm, queryOperation, operationValue));
	}


	// stores vector of query tuples <search ciphertext, operation type ciphertext, operation value ciphertext>
	std::vector<  tuple<std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>> > > 	queryCiphertextVector;



	// encrypt the queries and store in vector of tuples
	for (unsigned int i = 0; i < encodedPlaintextQueries.size(); ++i) {

		std::vector<shared_ptr<Ciphertext<Poly>>> searchTermCiphertext = cryptoContext->Encrypt(keyPair.publicKey, get<0>(encodedPlaintextQueries.at(i)), true);

		std::vector<shared_ptr<Ciphertext<Poly>>> queryOperationCiphertext = cryptoContext->Encrypt(keyPair.publicKey, get<1>(encodedPlaintextQueries.at(i)), true);

		std::vector<shared_ptr<Ciphertext<Poly>>> operationValueCiphertext = cryptoContext->Encrypt(keyPair.publicKey, get<2>(encodedPlaintextQueries.at(i)), true);

		queryCiphertextVector.push_back(std::tuple<std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>> >(searchTermCiphertext, queryOperationCiphertext, operationValueCiphertext));

	}



	// stores vector of query response <search ciphertext, return value>
	std::vector<  tuple<std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>> > > 	returnCiphertextVector;


	for (unsigned int i = 0; i < csvCiphertext.size(); ++i) {

		for (unsigned int j = 0; j < queryCiphertextVector.size(); ++j)
		{
			shared_ptr<Ciphertext<Poly>> ciphertextSub;

			ciphertextSub = cryptoContext->EvalSub(get<0>(csvCiphertext.at(i))[0], get<0>(queryCiphertextVector.at(j) )[0]);

			vector<shared_ptr<Ciphertext<Poly>>> ciphertextSubVect;
			ciphertextSubVect.push_back(ciphertextSub);

			IntPlaintextEncoding plaintextSub;
			cryptoContext->Decrypt(keyPair.secretKey, ciphertextSubVect, &plaintextSub, true);

			// std::cout << "IS A THING " << plaintextSub.EvalToInt(modulusVal) << endl;

			if(plaintextSub.EvalToInt(modulusVal) == 0){
				std::cout << "Have a match for name : " << get<0>(queries.at(j)) << endl;

				IntPlaintextEncoding plaintextOperation;
				cryptoContext->Decrypt(keyPair.secretKey, get<1>(queryCiphertextVector.at(j)), &plaintextOperation, true);

				int operationInt = plaintextOperation.EvalToInt(modulusVal);

				if(operationInt == 0){
					std::cout << "Is an add." << endl;

					shared_ptr<Ciphertext<Poly>> ciphertextAdd;
					vector<shared_ptr<Ciphertext<Poly>>> ciphertextAddVect;

					ciphertextAdd = cryptoContext->EvalAdd(get<2>(queryCiphertextVector.at(j))[0],  get<1>(csvCiphertext.at(i))[0]);

					ciphertextAddVect.push_back(ciphertextAdd);

					returnCiphertextVector.push_back( tuple<std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>> > (get<0>(queryCiphertextVector.at(j)), ciphertextAddVect));

				}

				else if(operationInt == 1){
					std::cout << "Is a sub." << endl;

					shared_ptr<Ciphertext<Poly>> ciphertextSub;
					vector<shared_ptr<Ciphertext<Poly>>> ciphertextSubVect;

					ciphertextSub = cryptoContext->EvalSub(get<1>(csvCiphertext.at(i))[0], get<2>(queryCiphertextVector.at(j))[0]);

					ciphertextSubVect.push_back(ciphertextSub);

					returnCiphertextVector.push_back( tuple<std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>> > (get<0>(queryCiphertextVector.at(j)), ciphertextSubVect));
				}

				else if(operationInt == 2){
					std::cout << "Is a mult." << endl;

					shared_ptr<Ciphertext<Poly>> ciphertextMult;
					vector<shared_ptr<Ciphertext<Poly>>> ciphertextMultVect;

					ciphertextMult = cryptoContext->EvalMult(get<2>(queryCiphertextVector.at(j))[0],  get<1>(csvCiphertext.at(i))[0]);

					ciphertextMultVect.push_back(ciphertextMult);

					returnCiphertextVector.push_back( tuple<std::vector<shared_ptr<Ciphertext<Poly>>>, std::vector<shared_ptr<Ciphertext<Poly>>> > (get<0>(queryCiphertextVector.at(j)), ciphertextMultVect));

				}

				else{
					std::cout << "Operation unknown." << endl;
				}
			}
		}


	}

	if(returnCiphertextVector.size() > 0){
		std::cout << "Are return values. " << endl;

		for (unsigned int i = 0; i < returnCiphertextVector.size(); ++i)
		{
			BytePlaintextEncoding decryptedName;
			cryptoContext->Decrypt(keyPair.secretKey, get<0>(returnCiphertextVector.at(i)), &decryptedName, true);

			IntPlaintextEncoding decryptedValue;
			cryptoContext->Decrypt(keyPair.secretKey, get<1>(returnCiphertextVector.at(i)), &decryptedValue, true);


			std::cout << "Name found : " << decryptedName << " with return value : " << decryptedValue.EvalToInt(modulusVal) << endl;
		}
	}

	


	return 0;


}
