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

#include <unistd.h>
#include <ios>

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


// returns in KB
void process_mem_usage(double& vm_usage, double& resident_set)
{
   using std::ios_base;
   using std::ifstream;
   using std::string;

   vm_usage     = 0.0;
   resident_set = 0.0;

   // 'file' stat seems to give the most reliable results
   //
   ifstream stat_stream("/proc/self/stat",ios_base::in);

   // dummy vars for leading entries in stat that we don't care about
   //
   string pid, comm, state, ppid, pgrp, session, tty_nr;
   string tpgid, flags, minflt, cminflt, majflt, cmajflt;
   string utime, stime, cutime, cstime, priority, nice;
   string O, itrealvalue, starttime;

   // the two fields we want
   //
   unsigned long vsize;
   long rss;

   stat_stream >> pid >> comm >> state >> ppid >> pgrp >> session >> tty_nr
               >> tpgid >> flags >> minflt >> cminflt >> majflt >> cmajflt
               >> utime >> stime >> cutime >> cstime >> priority >> nice
               >> O >> itrealvalue >> starttime >> vsize >> rss; // don't care about the rest

   stat_stream.close();

   long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024; // in case x86-64 is configured to use 2MB pages
   vm_usage     = vsize / 1024.0;
   resident_set = rss * page_size_kb;
}



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

	double total_vm_usage_start, total_resident_set_start;
	double total_vm_usage_end, total_resident_set_end;

	double vm_usage_start, resident_set_start;
	double vm_usage_end, resident_set_end;

	double key_pair_memory;

	double cryptoContextMemorySize; 
	// double total_plaintext_multiplicand_size, total_plaintext_multiplier_size;
	double total_ciphertext_multiplicand_size, total_ciphertext_multiplier_size;
	double total_ciphertext_result_size;


	// double average_plaintext_multiplicand_size, average_plaintext_multiplier_size;
	double average_ciphertext_multiplicand_size, average_ciphertext_multiplier_size;
	double average_ciphertext_result_size;

	vector<double> plaintextMultiplicandMemory;
	vector<double> plaintextMultiplierMemory;

	vector<double> ciphertextMultiplicandMemory;
	vector<double> ciphertextMultiplierMemory;

	vector<double> ciphertextResultsMemory;

	process_mem_usage(vm_usage_start, resident_set_start);
	shared_ptr<CryptoContext<Poly>> cryptoContext = CryptoContextHelper::getNewContext(schemeLabel);

	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);
	process_mem_usage(vm_usage_end, resident_set_end);

	cryptoContextMemorySize = vm_usage_end - vm_usage_start;


	process_mem_usage(vm_usage_start, resident_set_start);
	LPKeyPair<Poly> keyPair;
	keyPair = cryptoContext->KeyGen();
	process_mem_usage(vm_usage_end, resident_set_end);

	key_pair_memory = vm_usage_end - vm_usage_start;



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

	process_mem_usage(total_vm_usage_start, total_resident_set_start);
	for (unsigned int i = 0; i < vectorOfIntMultiplicands.size(); ++i)
	{	
		process_mem_usage(vm_usage_start, resident_set_start);
		
		// IntPlaintextEncoding plaintextMultiplicand(convertIntToBits(vectorOfIntMultiplicands.at(i)));

		IntPlaintextEncoding plaintextMultiplicand(vectorOfIntMultiplicands.at(i));
		process_mem_usage(vm_usage_end, resident_set_end);

		plaintextMultiplicandMemory.push_back((vm_usage_end - vm_usage_start));

		plaintextVectorOfMultiplicands.push_back(plaintextMultiplicand);

		// cout << "Multiplicand " << plaintextMultiplicand << endl;
	}
	process_mem_usage(total_vm_usage_end, total_resident_set_end);
	// total_plaintext_multiplicand_size = total_vm_usage_end - total_vm_usage_start;
	// average_plaintext_multiplicand_size = total_plaintext_multiplicand_size/(static_cast<int>(vectorOfIntMultiplicands.size()));


	// endcode multipliers
	process_mem_usage(total_vm_usage_start, total_resident_set_start);
	for (unsigned int i = 0; i < vectorOfIntMultipliers.size(); ++i)
	{

		process_mem_usage(vm_usage_start, resident_set_start);

		IntPlaintextEncoding plaintextMultiplier(vectorOfIntMultipliers.at(i));
		// IntPlaintextEncoding plaintextMultiplier(convertIntToBits(vectorOfIntMultipliers.at(i)));
		process_mem_usage(vm_usage_end, resident_set_end);

		plaintextMultiplierMemory.push_back((vm_usage_end - vm_usage_start));


		plaintextVectorOfMultipliers.push_back(plaintextMultiplier);

		// cout << "Multiplier " << plaintextMultiplier << endl;
	}
	process_mem_usage(total_vm_usage_end, total_resident_set_end);
	// total_plaintext_multiplier_size = total_vm_usage_end - total_vm_usage_start;
	// average_plaintext_multiplier_size = total_plaintext_multiplier_size/(static_cast<double>(vectorOfIntMultipliers.size()));


	std::vector<vector<shared_ptr<Ciphertext<Poly>>>> ciphertextVectorOfMultiplicands;
	std::vector<vector<shared_ptr<Ciphertext<Poly>>>> ciphertextVectorOfMultipliers;


	// encrpyt multiplicands
	process_mem_usage(total_vm_usage_start, total_resident_set_start);
	for (unsigned int i = 0; i < plaintextVectorOfMultiplicands.size(); ++i)
	{	
		vector<shared_ptr<Ciphertext<Poly>>> ciphertextMultiplicand;

		process_mem_usage(vm_usage_start, resident_set_start);
		ciphertextMultiplicand = cryptoContext->Encrypt(keyPair.publicKey, plaintextVectorOfMultiplicands.at(i), true);
		process_mem_usage(vm_usage_end, resident_set_end);

		ciphertextMultiplicandMemory.push_back((vm_usage_end - vm_usage_start));


		ciphertextVectorOfMultiplicands.push_back(ciphertextMultiplicand);
	}
	process_mem_usage(total_vm_usage_end, total_resident_set_end);
	total_ciphertext_multiplicand_size = total_vm_usage_end - total_vm_usage_start;
	average_ciphertext_multiplicand_size = total_ciphertext_multiplicand_size/(static_cast<double>(ciphertextVectorOfMultiplicands.size()));



	// encrpyt multipliers
	process_mem_usage(total_vm_usage_start, total_resident_set_start);
	for (unsigned int i = 0; i < plaintextVectorOfMultipliers.size(); ++i)
	{
		vector<shared_ptr<Ciphertext<Poly>>> ciphertextMultiplier;

		process_mem_usage(vm_usage_start, resident_set_start);
		ciphertextMultiplier = cryptoContext->Encrypt(keyPair.publicKey, plaintextVectorOfMultipliers.at(i), true);
		process_mem_usage(vm_usage_end, resident_set_end);

		ciphertextMultiplierMemory.push_back((vm_usage_end - vm_usage_start));


		ciphertextVectorOfMultipliers.push_back(ciphertextMultiplier);
	}
	process_mem_usage(total_vm_usage_end, total_resident_set_end);
	total_ciphertext_multiplier_size = total_vm_usage_end - total_vm_usage_start;
	average_ciphertext_multiplier_size = total_ciphertext_multiplier_size/(static_cast<double>(ciphertextVectorOfMultipliers.size()));


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


	process_mem_usage(total_vm_usage_start, total_resident_set_start);

	for (unsigned int i = 0; i < ciphertextVectorOfMultiplicands.size(); ++i)
	{
		for (unsigned int j = 0; j < ciphertextVectorOfMultipliers.size(); ++j)
		{
			shared_ptr<Ciphertext<Poly>> ciphertextMul;

			vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVec;

			process_mem_usage(vm_usage_start, resident_set_start);
			ciphertextMul = cryptoContext->EvalMult(ciphertextVectorOfMultiplicands.at(i)[0],ciphertextVectorOfMultipliers.at(j)[0]);
			process_mem_usage(vm_usage_end, resident_set_end);


			ciphertextResultsMemory.push_back((vm_usage_end - vm_usage_start));

			ciphertextMulVec.push_back(ciphertextMul);

			ciphertextMultResults.push_back(ciphertextMulVec);
		}
	}

	process_mem_usage(total_vm_usage_end, total_resident_set_end);

	total_ciphertext_result_size = total_vm_usage_end - total_vm_usage_start;
	average_ciphertext_result_size = total_ciphertext_result_size/(static_cast<double>(ciphertextMultResults.size()));



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
		// std::cout << vectorOfIntMultiplicands.at(multiplicandIndex) << " X " << vectorOfIntMultipliers.at(multiplierIndex) << " = " << convertIntPlaintextEncodingToUint(multResult) << endl;

		std::cout << vectorOfIntMultiplicands.at(multiplicandIndex) << " X " << vectorOfIntMultipliers.at(multiplierIndex) << " = " << multResult.EvalToInt(cryptoContext->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt()) << endl;

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

	// cout << "pub key object memory : " << sizeof(*keyPair.publicKey) << endl;
	cout << "pub key serialized file size : " << pubKeyFileSize/1000 << " KB" << endl;
	// Serialize private key
	
	Serialized privK;
	keyPair.secretKey->Serialize(&privK);
	SerializableHelper::WriteSerializationToFile(privK, privkeyFileName);

	int privKeyFileSize = GetFileSize(privkeyFileName);

	remove(privkeyFileName.c_str());

	// cout << "priv key object memory : " << sizeof(*keyPair.secretKey) << endl;
	cout << "priv key serialized file size : " << privKeyFileSize/1000 << " KB" << endl;

	double total_key_file_memory = privKeyFileSize + pubKeyFileSize;

	cout << "total key serialized file size : " << total_key_file_memory/1000 << " KB" << endl;

	std::cout << "Key pair memory : " << key_pair_memory/1000 << " KB" << endl;

	vector<long> multiplicandSizes;
	vector<long> multiplierSizes;

	vector<long> multResultSizes;

	// cout << "Average plaintext multiplier memory size : " << average_plaintext_multiplier_size << " KB" << endl << endl;
	// cout << "Average plaintext multiplicand memory size : " << average_plaintext_multiplicand_size << " KB" << endl << endl;
	
	cout << endl;

	// serialize original multiplicand ciphertexts
	for (unsigned int i = 0; i < ciphertextVectorOfMultiplicands.size(); ++i) {

		Serialized cSer;
		ciphertextVectorOfMultiplicands.at(i)[0]->Serialize(&cSer);
		SerializableHelper::WriteSerializationToFile(cSer, ciphertextMultiplicandFilePrefix + to_string(i) + ".txt");
		long ciphertextFileSize = GetFileSize(ciphertextMultiplicandFilePrefix + to_string(i) + ".txt");

		remove((ciphertextMultiplicandFilePrefix + to_string(i) + ".txt").c_str());

		multiplicandSizes.push_back(ciphertextFileSize);

		
		// cout << "Pre mul cipher serialized file size : " << ciphertextFileSize << endl;

		//std::cout << "Pre mul ciphertext virtual memory : " << plaintextMultiplicandMemory.at(i) << " KB" << endl;
	}
	float averageCipherMultiplicandSerializedFileSize = accumulate(multiplicandSizes.begin(), multiplicandSizes.end(), 0.0)/multiplicandSizes.size();

	cout << "Pre mul average cipher multiplicand serialized file size : " << averageCipherMultiplicandSerializedFileSize/1000 << " KB" << endl;


	cout << "Pre mul average cipher multiplicand memory size : " << average_ciphertext_multiplicand_size << " KB";
	cout << endl;

	// serialize original multiplier ciphertexts
	for (unsigned int i = 0; i < ciphertextVectorOfMultipliers.size(); ++i) {

		Serialized cSer;
		ciphertextVectorOfMultipliers.at(i)[0]->Serialize(&cSer);
		SerializableHelper::WriteSerializationToFile(cSer, ciphertextMultiplierFilePrefix + to_string(i) + ".txt");
		long ciphertextFileSize = GetFileSize(ciphertextMultiplierFilePrefix + to_string(i) + ".txt");

		remove((ciphertextMultiplierFilePrefix + to_string(i) + ".txt").c_str());

		multiplierSizes.push_back(ciphertextFileSize);

		
		// cout << "Pre mul cipher serialized file size : " << ciphertextFileSize << endl;

		// std::cout << "Pre mul ciphertext virtual memory : " << plaintextMultiplierMemory.at(i) << " KB" << endl;
	}

	float averageCipherMultiplierSerializedFileSize = accumulate(multiplierSizes.begin(), multiplierSizes.end(), 0.0)/multiplierSizes.size();

	cout << "Pre mul average cipher multiplier serialized file size : " << averageCipherMultiplierSerializedFileSize/1000 << " KB" << endl;


	cout << "Pre mul average cipher multiplier memory size : " << average_ciphertext_multiplier_size << " KB";
	cout << endl;

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

		// cout << "Post mul cipher serialized file size : " << ciphertextFileSize << endl;

		// std::cout << "Post mul ciphertext virtual memory : " << ciphertextResultsMemory.at(i) << " KB" << endl;
	}

	float averageCipherResultSerializedFileSize = accumulate(multResultSizes.begin(), multResultSizes.end(), 0.0)/multResultSizes.size();

	cout << "Post mul average cipher serialized file size : " << averageCipherResultSerializedFileSize/1000 << " KB" << endl;

	cout << "Post mul average cipher memory size : " << average_ciphertext_result_size << " KB";
	cout << endl << endl;


	// serialize the crypto context
	Serialized cSer;
	cryptoContext->Serialize(&cSer);
	SerializableHelper::WriteSerializationToFile(cSer, cryptoContextSerializeFilePrefix);
	long cryptoContextFileSize = GetFileSize(cryptoContextSerializeFilePrefix);

	remove(cryptoContextSerializeFilePrefix.c_str());

	// cout << "Crypto object memory " << sizeof(*cryptoContext) << endl;
	cout << "Crypto Context object serialized file size " << cryptoContextFileSize/1000 << " KB" << endl << endl;
	cout << "Crypto Context memory size : " << cryptoContextMemorySize << " KB" << endl;
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

	if(argc > 1){
		cout << "Running for scheme  " << argv[1] << endl;
		runOperations(std::string(argv[1]));
		return 1;
	}

	double outside_vm_usage_start, outside_resident_set_start, outside_vm_usage_end, outside_resident_set_end;

	for (unsigned int i = 0; i < allSchemes.size(); ++i)
	{
		try{
			std::cout << "Running operations for " << allSchemes.at(i) << endl;
			process_mem_usage(outside_vm_usage_start, outside_resident_set_start);
			runOperations(allSchemes.at(i));
			process_mem_usage(outside_vm_usage_end, outside_resident_set_end);

			cout << "Total outside mem diff: " << (outside_vm_usage_end - outside_vm_usage_start) << " KB" << endl << endl;
			std::cout << "Success." << endl << endl << endl;
			sleep(2);
		} catch (const std::exception &e){
			std::cout << "Exception caught " << e.what() << endl;
		}
		
	}


	return 0;
}
