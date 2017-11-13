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

	string namesAndValues = "AlanBo,2\nJeffBoboboTAA,1\nEmilyBoboboWOO,3\n";

	std::vector<tuple<BytePlaintextEncoding,IntPlaintextEncoding>> newEncodedPlaintext = getEncodedPlaintextFromCSV(namesAndValues);


	// print for sanity check
	for (unsigned int i = 0; i < newEncodedPlaintext.size(); ++i) {

		std::cout << "new Names vector plaintext : " << get<0>(newEncodedPlaintext.at(i)) << endl;
		std::cout << "new Values vector plaintext : " << get<1>(newEncodedPlaintext.at(i)) << endl;
	}


	// StSt6 uses plaintext modulus of 256
	string input = "StSt6";

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



	LPKeyPair<Poly> keyPair;
	keyPair = cryptoContext->KeyGen();


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

	for (int i = 0; i < vectorSize; ++i) {
		BytePlaintextEncoding namePlaintextDec;
		cryptoContext->Decrypt(keyPair.secretKey, namesCiphertextVector.at(i), &namePlaintextDec, true);
		namePlaintextDec.resize(namesPlaintextVector.at(i).size());

		std::cout << "Name plaintext decrypted : " << namePlaintextDec << endl;

		IntPlaintextEncoding valuePlaintextDec;
		cryptoContext->Decrypt(keyPair.secretKey, valuesCiphertextVector.at(i), &valuePlaintextDec, true);
		valuePlaintextDec.resize(valuesPlaintextVector.at(i).size());

		std::cout << "Value plaintext decrypted : " << valuePlaintextDec << endl;

		std::cout << endl;
	}

	return 1;
	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////

	//Generate parameters.
	double diff, start, finish;

	int vectorSize = 0;

	

	std::vector<string> 	namesVector 	= {};
	std::vector<uint32_t> 	valuesVector 	= {};

	std::istringstream ss(namesAndValues);
	std::string line;

	// break input on newline

	std::string name;
	std::string value;
	

	while(std::getline(ss, line)) {

		std::istringstream line_ss(line);

		std::getline(line_ss, name, ',');
		namesVector.push_back(name);

		std::getline(line_ss, value);

		std::istringstream to_uint_reader(value);
		uint32_t uint_val;

		to_uint_reader >> uint_val;

		valuesVector.push_back(uint_val);

		vectorSize++;
	    
	}

	for (int i = 0; i < vectorSize; ++i) {
		std::cout << namesVector.at(i) << ' ' << valuesVector.at(i) << endl;
	}
	// for(auto i: namesVector)
	// 	std::cout << i << endl;

	// return -1;



	
	std::vector<BytePlaintextEncoding> 	namesPlaintextVector;
	std::vector<IntPlaintextEncoding> 	valuesPlaintextVector;

	for (int i = 0; i < vectorSize; ++i) {
		BytePlaintextEncoding namesPlaintext(namesVector.at(i));
		namesPlaintextVector.push_back(namesPlaintext);

		std::cout << "Names vector plaintext : " << namesPlaintext << endl;

		IntPlaintextEncoding valuesPlaintext(valuesVector.at(i));
		valuesPlaintextVector.push_back(valuesPlaintext);

		std::cout << "Values vector plaintext : " << valuesPlaintext << endl;

	}
	

	// LPKeyPair<Poly> keyPair;
	// keyPair = cryptoContext->KeyGen();

	std::vector< std::vector<shared_ptr<Ciphertext<Poly>>> > 	namesCiphertextVector;
	std::vector< std::vector<shared_ptr<Ciphertext<Poly>>> > 	valuesCiphertextVector;

	for (int i = 0; i < vectorSize; ++i) {
		std::vector<shared_ptr<Ciphertext<Poly>>> nameCiphertext = cryptoContext->Encrypt(keyPair.publicKey, namesPlaintextVector.at(i), true);
		namesCiphertextVector.push_back(nameCiphertext);

		std::cout << "name ciphertext : ";

		for (unsigned int j = 0; j < nameCiphertext.size(); ++j) {
			std::cout << nameCiphertext.at(j) << ' ';
		}

		std::cout << "Name ciphertext size: " << nameCiphertext.size() << endl;

		std::vector<shared_ptr<Ciphertext<Poly>>> valueCiphertext = cryptoContext->Encrypt(keyPair.publicKey, valuesPlaintextVector.at(i), true);
		valuesCiphertextVector.push_back(valueCiphertext);

		std::cout << endl;
		std::cout << "value ciphertext : ";

		for (unsigned int j = 0; j < valueCiphertext.size(); ++j) {
			std::cout << valueCiphertext.at(j) << ' ';
		}

		std::cout << endl;
	}

	

	






	std::string searchName = "JeffBoboboTAA";
	BytePlaintextEncoding searchNamePlaintext(searchName);


	std::vector<shared_ptr<Ciphertext<Poly>>> searchNameCiphertext = cryptoContext->Encrypt(keyPair.publicKey, searchNamePlaintext, true);
	

	std::cout << "Search name ciphertext 1 :  ";

	for (unsigned int j = 0; j < searchNameCiphertext.size(); ++j) {
		std::cout << searchNameCiphertext.at(j) << ' ';
	}

	std::cout << endl;


	BytePlaintextEncoding searchNamePlaintextDec;
	cryptoContext->Decrypt(keyPair.secretKey, searchNameCiphertext, &searchNamePlaintextDec, true);
	searchNamePlaintextDec.resize(searchNamePlaintext.size());

	std::cout << "Search name dec 1 : " << searchNamePlaintextDec << endl;
	std::cout << endl;






	std::string searchName2 = "JeffBoboboTAAB";
	BytePlaintextEncoding searchNamePlaintext2(searchName2);


	std::vector<shared_ptr<Ciphertext<Poly>>> searchNameCiphertext2 = cryptoContext->Encrypt(keyPair.publicKey, searchNamePlaintext2, true);
	
	std::cout << "Search name ciphertext 2 :  ";

	std::cout << searchNameCiphertext2[0];
	std::cout << endl;



	BytePlaintextEncoding searchNamePlaintextDec2;
	cryptoContext->Decrypt(keyPair.secretKey, searchNameCiphertext2, &searchNamePlaintextDec2, true);
	searchNamePlaintextDec2.resize(searchNamePlaintext2.size());

	std::cout << "Search name dec 2 : " << searchNamePlaintextDec2 << endl;


	std::cout << endl;







	shared_ptr<Ciphertext<Poly>> ciphertextSub12;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextSubVect;

	std::cout << "Search name ciphertext 1 : " << searchNameCiphertext[0] << endl;
	std::cout << "Search name ciphertext 2 : " << searchNameCiphertext2[0] << endl;


	BytePlaintextEncoding plaintext1;

	cryptoContext->Decrypt(keyPair.secretKey, searchNameCiphertext, &plaintext1, true);

	plaintext1.resize(searchNamePlaintext2.size());

	std::cout << "Plaintext 1 out : " << plaintext1 << endl;



	BytePlaintextEncoding plaintext2;

	cryptoContext->Decrypt(keyPair.secretKey, searchNameCiphertext2, &plaintext2, true);

	plaintext2.resize(searchNamePlaintext2.size());

	std::cout << "Plaintext 2 out : " << plaintext2 << endl;




	ciphertextSub12 = cryptoContext->EvalSub(searchNameCiphertext[0],searchNameCiphertext2[0]);

	ciphertextSubVect.push_back(ciphertextSub12);



	IntPlaintextEncoding plaintextSub;

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSubVect, &plaintextSub, true);

	plaintextSub.resize(searchNamePlaintext2.size());



	cout << "\n Resulting Sub Plaintext: \n";
	cout << plaintextSub << endl;

	cout << "Result eval to int : " << plaintextSub.EvalToInt(256*searchNamePlaintext2.size()) << endl;

	return -1;







	std::string searchName3 = "JeffBoboboTAA";
	BytePlaintextEncoding searchNamePlaintext3(searchName);


	std::vector<shared_ptr<Ciphertext<Poly>>> searchNameCiphertext3 = cryptoContext->Encrypt(keyPair.publicKey, searchNamePlaintext3, true);
	

	std::cout << "Search name ciphertext 3 :  ";

	std::cout << searchNameCiphertext3[0];
	std::cout << endl;


	BytePlaintextEncoding searchNamePlaintextDec3;
	cryptoContext->Decrypt(keyPair.secretKey, searchNameCiphertext3, &searchNamePlaintextDec3, true);
	searchNamePlaintextDec3.resize(searchNamePlaintext3.size());

	std::cout << "Search name dec 3 : " << searchNamePlaintextDec3 << endl;


	std::cout << endl;







	std::string searchName4 = "JeffBoboboTAA";
	BytePlaintextEncoding searchNamePlaintext4(searchName);


	std::vector<shared_ptr<Ciphertext<Poly>>> searchNameCiphertext4 = cryptoContext->Encrypt(keyPair.publicKey, searchNamePlaintext4, true);
	

	std::cout << "Search name ciphertext 4 :  ";

	std::cout << searchNameCiphertext4[0];

	std::cout << endl;

	BytePlaintextEncoding searchNamePlaintextDec4;
	cryptoContext->Decrypt(keyPair.secretKey, searchNameCiphertext4, &searchNamePlaintextDec4, true);
	searchNamePlaintextDec4.resize(searchNamePlaintext4.size());

	std::cout << "Search name dec 4 : " << searchNamePlaintextDec4 << endl;


	std::cout << endl;





	// for (int i = 0; i < vectorSize; ++i) {

	// 	std::cout << "Names vector ciphertext : ";

	// 	for (unsigned int j = 0; j < namesCiphertextVector.at(i).size(); ++j) {
	// 		std::cout << namesCiphertextVector.at(i).at(j) << ' ';
	// 	}

	// 	std::cout << endl;

	// 	std::cout << "Search name ciphertext :  ";

	// 	for (unsigned int j = 0; j < searchNameCiphertext.size(); ++j) {
	// 		std::cout << searchNameCiphertext.at(j) << ' ';
	// 	}

	// 	std::cout << endl;
	// 	std::cout << endl;

	// }


	// return 1;







	std::cout << "\nThis code demonstrates the use of the FV, BV, StSt, Null and LTV schemes for basic public-key encryption. " << std::endl;
	std::cout << "This code shows how to use schemes and pre-computed parameters for those schemes can be selected during run-time. " << std::endl;
	std::cout << "We do not generally recommend the use of the LTV scheme due to security concerns. " << std::endl;
	
	std::cout << "Choose parameter set: ";
	CryptoContextHelper::printAllParmSetNames(std::cout);

	std::cin >> input;

	start = currentDateTime();


	finish = currentDateTime();
	diff = finish - start;

	cout << "Param generation time: " << "\t" << diff << " ms" << endl;

	//cryptoContext<Poly> cryptoContext = GencryptoContextElementLTV(ORDER, PTM);

	//Turn on features
	cryptoContext->Enable(ENCRYPTION);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();
	
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts = {1,1,1,0,1,1,0,1,0,0,0,0};
	IntPlaintextEncoding plaintext(vectorOfInts);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	start = currentDateTime();

	ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext, true);
	
	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &plaintextDec, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintextDec.resize(plaintext.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintextDec << endl;

	cout << "\n";


	////////////////////////////////////////////////////////////
	// Done
	////////////////////////////////////////////////////////////

	std::cout << "Execution Completed. DUUUUUH." << std::endl;

	return 0;
}
