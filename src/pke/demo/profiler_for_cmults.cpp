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


#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

using namespace std;
using namespace lbcrypto;


long GetFileSize(std::string filename)
{
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}



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


int runOperations(string schemeLabel)
{

	shared_ptr<CryptoContext<Poly>> cryptoContext = CryptoContextHelper::getNewContext(schemeLabel);

	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	LPKeyPair<Poly> keyPair;

	keyPair = cryptoContext->KeyGen();
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);


	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////


	std::vector<uint32_t> vectorOfIntMultiplicands = {1,2,3,4,5};
	std::vector<uint32_t> vectorOfIntMultipliers = {6,7,8,9,10};

	// for (unsigned int i = 0; i < vectorOfIntMultiplicands.size(); ++i)
	// {
	// 	vector<uint32_t> bitwiseVector = convertIntToBits( vectorOfIntMultiplicands.at(i) );
	// 	for (unsigned int j = 0; j < bitwiseVector.size(); ++j)
	// 	{
	// 		cout <<  bitwiseVector.at(j) << ":";
	// 	}

	// 	IntPlaintextEncoding thisVec(bitwiseVector);
	// 	cout << "bit vec : " <<  thisVec.EvalToInt(5) << endl;
	// 	cout << endl;
	// }

	// exit(1);
	std::vector<IntPlaintextEncoding> plaintextVectorOfMultiplicands;
	std::vector<IntPlaintextEncoding> plaintextVectorOfMultipliers;

	// encode multiplicands
	for (unsigned int i = 0; i < vectorOfIntMultiplicands.size(); ++i)
	{
		IntPlaintextEncoding plaintextMultiplicand(convertIntToBits(vectorOfIntMultiplicands.at(i)));
		plaintextVectorOfMultiplicands.push_back(plaintextMultiplicand);

		// cout << "Multiplicand " << plaintextMultiplicand << endl;
	}

	// endcode multipliers
	for (unsigned int i = 0; i < vectorOfIntMultipliers.size(); ++i)
	{
		IntPlaintextEncoding plaintextMultiplier(convertIntToBits(vectorOfIntMultipliers.at(i)));
		plaintextVectorOfMultipliers.push_back(plaintextMultiplier);

		// cout << "Multiplier " << plaintextMultiplier << endl;
	}


	std::vector<vector<shared_ptr<Ciphertext<Poly>>>> ciphertextVectorOfMultiplicands;
	std::vector<vector<shared_ptr<Ciphertext<Poly>>>> ciphertextVectorOfMultipliers;

	// encrpyt multiplicands
	for (unsigned int i = 0; i < plaintextVectorOfMultiplicands.size(); ++i)
	{
		vector<shared_ptr<Ciphertext<Poly>>> ciphertextMultiplicand;
		ciphertextMultiplicand = cryptoContext->Encrypt(keyPair.publicKey, plaintextVectorOfMultiplicands.at(i), true);

		ciphertextVectorOfMultiplicands.push_back(ciphertextMultiplicand);
	}


	// encrpyt multipliers
	for (unsigned int i = 0; i < plaintextVectorOfMultipliers.size(); ++i)
	{
		vector<shared_ptr<Ciphertext<Poly>>> ciphertextMultiplier;
		ciphertextMultiplier = cryptoContext->Encrypt(keyPair.publicKey, plaintextVectorOfMultipliers.at(i), true);

		ciphertextVectorOfMultipliers.push_back(ciphertextMultiplier);
	}




/*
	////////////////////////////////////////////////////////////
	// EvalAdd Operation
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextAdd12;
	shared_ptr<Ciphertext<Poly>> ciphertextAdd123;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextAddVect;


	ciphertextAdd12 = cryptoContext->EvalAdd(ciphertext1[0],ciphertext2[0]);
	ciphertextAdd123 = cryptoContext->EvalAdd(ciphertextAdd12,ciphertext3[0]);

	ciphertextAddVect.push_back(ciphertextAdd123);

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAdd;

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddVect, &plaintextAdd, true);

	plaintextAdd.resize(plaintext1.size());
*/



	////////////////////////////////////////////////////////////
	// EvalMult Operations
	////////////////////////////////////////////////////////////

	//Generate parameters.
	double diff, start, finish;

	start = currentDateTime();

	std::vector<vector<shared_ptr<Ciphertext<Poly>>>> ciphertextMultResults;

	for (unsigned int i = 0; i < ciphertextVectorOfMultiplicands.size(); ++i)
	{
		for (unsigned int j = 0; j < ciphertextVectorOfMultipliers.size(); ++j)
		{
			shared_ptr<Ciphertext<Poly>> ciphertextMul;

			vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVec;

			ciphertextMul = cryptoContext->EvalMult(ciphertextVectorOfMultiplicands.at(i)[0],ciphertextVectorOfMultipliers.at(j)[0]);
			ciphertextMulVec.push_back(ciphertextMul);

			ciphertextMultResults.push_back(ciphertextMulVec);
		}
	}

	finish = currentDateTime();
	diff = finish - start;




	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	vector<IntPlaintextEncoding> plaintextMultResults;
	unsigned int multiplicandIndex;
	unsigned int multiplierIndex;
	for (unsigned int i = 0; i < ciphertextMultResults.size(); ++i)
	{
		IntPlaintextEncoding multResult;
		cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResults.at(i), &multResult, true);
		multResult.resize(plaintextVectorOfMultiplicands.at(0).size());
		plaintextMultResults.push_back(multResult);

		multiplicandIndex = i /5;

		multiplierIndex = i%5;
		std::cout << vectorOfIntMultiplicands.at(multiplicandIndex) << " X " << vectorOfIntMultipliers.at(multiplierIndex) << " = " << convertIntPlaintextEncodingToUint(multResult) << endl;

		// if(vectorOfIntMultiplicands.at(multiplicandIndex) * vectorOfIntMultipliers.at(multiplierIndex) != convertIntPlaintextEncodingToUint(multResult)){
		// 	cout << "error " << endl << multResult << endl;

		// 	cout << "multiplicand : " << endl << plaintextVectorOfMultiplicands.at(multiplicandIndex) << endl;

		// 	cout << "multiplier : " << endl << plaintextVectorOfMultipliers.at(multiplierIndex) << endl << endl;
		// }

	}

	cout << "25 Cmults Time in ms : " << diff << endl << endl;
	

	////////////////////////////////////////////////////////////
	//Perform Serialization for object disk space testing
	////////////////////////////////////////////////////////////
	
	std::string DATAFOLDER = "demoData";
	std::string pubkeyFileName = DATAFOLDER + "/" + "for_profiling_" + schemeLabel + "_PUB.txt";
	std::string privkeyFileName = DATAFOLDER + "/" + "for_profiling_" + schemeLabel + "_PRI.txt";

	std::string ciphertextMultiplierFilePrefix = DATAFOLDER + "/" + "for_profiling_" + schemeLabel + "_ctext_mplier_";
	std::string ciphertextMultiplicandFilePrefix = DATAFOLDER + "/" + "for_profiling_" + schemeLabel + "_ctext_mplicand_";

	std::string ciphertextMultResultFilePrefix = DATAFOLDER + "/" + "for_profiling_" + schemeLabel + "_ctext_mresult_";


	std::string cryptoContextSerializeFilePrefix = DATAFOLDER + "/" + "for_profiling_" + schemeLabel + "_cc.txt";
	// Serialize public key
	
	Serialized pubK;
	keyPair.publicKey->Serialize(&pubK);
	SerializableHelper::WriteSerializationToFile(pubK, pubkeyFileName);

	int pubKeyFileSize = GetFileSize(pubkeyFileName);

	remove(pubkeyFileName.c_str());

	cout << "pub key object memory : " << sizeof(*keyPair.publicKey) << endl;
	cout << "pub key size : " << pubKeyFileSize << endl;
	// Serialize private key
	
	Serialized privK;
	keyPair.secretKey->Serialize(&privK);
	SerializableHelper::WriteSerializationToFile(privK, privkeyFileName);

	int privKeyFileSize = GetFileSize(privkeyFileName);

	remove(privkeyFileName.c_str());

	cout << "priv key object memory : " << sizeof(*keyPair.secretKey) << endl;
	cout << "priv key size : " << privKeyFileSize << endl;



	vector<long> multiplicandSizes;
	vector<long> multiplierSizes;

	vector<long> multResultSizes;

	// serialize original multiplicand ciphertexts
	for (unsigned int i = 0; i < ciphertextVectorOfMultiplicands.size(); ++i) {

		Serialized cSer;
		ciphertextVectorOfMultiplicands.at(i)[0]->Serialize(&cSer);
		SerializableHelper::WriteSerializationToFile(cSer, ciphertextMultiplicandFilePrefix + to_string(i) + ".txt");
		long ciphertextFileSize = GetFileSize(ciphertextMultiplicandFilePrefix + to_string(i) + ".txt");

		remove((ciphertextMultiplicandFilePrefix + to_string(i) + ".txt").c_str());

		multiplicandSizes.push_back(ciphertextFileSize);

		cout << "Pre mul cipher object memory : " << sizeof(ciphertextVectorOfMultiplicands.at(i)[0]->GetElements()) << endl;
		cout << "Pre mul cipher size : " << ciphertextFileSize << endl;
	}


	// serialize original multiplier ciphertexts
	for (unsigned int i = 0; i < ciphertextVectorOfMultipliers.size(); ++i) {

		Serialized cSer;
		ciphertextVectorOfMultipliers.at(i)[0]->Serialize(&cSer);
		SerializableHelper::WriteSerializationToFile(cSer, ciphertextMultiplierFilePrefix + to_string(i) + ".txt");
		long ciphertextFileSize = GetFileSize(ciphertextMultiplierFilePrefix + to_string(i) + ".txt");

		remove((ciphertextMultiplierFilePrefix + to_string(i) + ".txt").c_str());

		multiplierSizes.push_back(ciphertextFileSize);

		cout << "Pre mul cipher object memory : " << sizeof(ciphertextVectorOfMultipliers.at(i)[0]->GetElements()) << endl;
		cout << "Pre mul cipher size : " << ciphertextFileSize << endl;
	}

	cout << endl;

	// serialize multiply result ciphertexts

	for (unsigned int i = 0; i < ciphertextMultResults.size(); ++i)
	{

		Serialized cSer;
		ciphertextMultResults.at(i)[0]->Serialize(&cSer);
		SerializableHelper::WriteSerializationToFile(cSer, ciphertextMultResultFilePrefix + to_string(i) + ".txt");
		long ciphertextFileSize = GetFileSize(ciphertextMultResultFilePrefix + to_string(i) + ".txt");

		remove((ciphertextMultResultFilePrefix + to_string(i) + ".txt").c_str());

		multResultSizes.push_back(ciphertextFileSize);

		cout << "Post mul cipher object memory : " << sizeof(ciphertextMultResults.at(i)[0]->GetElements()) << endl;
		cout << "Post mul cipher size : " << ciphertextFileSize << endl;
	}


	// serialize the crypto context
	Serialized cSer;
	cryptoContext->Serialize(&cSer);
	SerializableHelper::WriteSerializationToFile(cSer, cryptoContextSerializeFilePrefix);
	long cryptoContextFileSize = GetFileSize(cryptoContextSerializeFilePrefix);

	remove(cryptoContextSerializeFilePrefix.c_str());

	cout << "Crypto object memory " << sizeof(*cryptoContext) << endl;
	cout << "Crypto size " << cryptoContextFileSize << endl << endl;

	return 1;
}


int main(int argc, char *argv[]) {


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
		try{
			std::cout << "Running operations for " << allSchemes.at(i) << endl;
			runOperations(allSchemes.at(i));
			std::cout << "Success." << endl << endl;
		} catch (const std::exception &e){
			std::cout << "Exception caught " << e.what() << endl;
		}
		
	}


	return 0;
}
