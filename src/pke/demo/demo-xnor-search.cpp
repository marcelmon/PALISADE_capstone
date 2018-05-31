
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



Ciphertext<PolyType> encrypt_int( CryptoContext<PolyType> cc, LPKeyPair<PolyType> keyPair, uint32_t val )
{
	Plaintext encodedInt = cc->MakeIntegerPlaintext(val);
	Ciphertext<PolyType> ctext_ret = cc->Encrypt(keyPair.publicKey, encodedInt);
	return ctext_ret;
}


/*
	Requires that each ciphertext was a single encrypted bit
	Returns the ciphertext result of the xnor

	Start with an encrypted 1 value, perform subs and mults and an add, then final mult and return result
*/
Ciphertext<PolyType> do_binary_xnor(
	CryptoContext<PolyType> cc,
	LPKeyPair<PolyType> keyPair,
	Ciphertext<PolyType> ctext_val_1, 
	Ciphertext<PolyType> ctext_val_2
	) {

	Ciphertext<PolyType> ctext_one = encrypt_int(cc, keyPair, 1);

	// A' = A - 1
	// B' = B - 1
	Ciphertext<PolyType> val1BitMinus1 = cc->EvalSub(ctext_val_1, ctext_one);
	Ciphertext<PolyType> val2BitMinus1 = cc->EvalSub(ctext_val_2, ctext_one);

	// C = (A x B)+(A' x B')
	Ciphertext<PolyType> xnorLeftResult = cc->EvalMult(ctext_val_1, ctext_val_2);
	Ciphertext<PolyType> xnorrightResult = cc->EvalMult(val1BitMinus1, val2BitMinus1);
	Ciphertext<PolyType> xnorResultBoth = cc->EvalAdd(xnorLeftResult, xnorrightResult);

	// 1 X C
	// xnorResult = cc->EvalMult(xnorResult, xnorResultBoth);

	return xnorResultBoth;
}



Ciphertext<PolyType> do_chained_binary_xnor(
	CryptoContext<PolyType> cc,
	LPKeyPair<PolyType> keyPair,
	vector<Ciphertext<PolyType>> ctext_vals_1, 
	vector<Ciphertext<PolyType>> ctext_vals_2
	){

	if(ctext_vals_1.size() != ctext_vals_2.size()){
		// throw new error!
		return NULL;
	}

	Ciphertext<PolyType> xnorResult = encrypt_int(cc, keyPair, 1);

	for (unsigned int i = 0; i < ctext_vals_1.size(); ++i)
	{
		Ciphertext<PolyType> val1Bit = ctext_vals_1.at(i);
		Ciphertext<PolyType> val2Bit = ctext_vals_2.at(i);

		Ciphertext<PolyType> singleBinaryXnorRes = do_binary_xnor(cc, keyPair, val1Bit, val2Bit);

		xnorResult = cc->EvalMult(xnorResult, singleBinaryXnorRes);
	}


	return xnorResult;
}


Ciphertext<PolyType> do_chained_binary_xnor_query(
	CryptoContext<PolyType> cc,
	LPKeyPair<PolyType> keyPair,
	vector<Ciphertext<PolyType>> ctext_vals_1, 
	vector<Ciphertext<PolyType>> ctext_vals_2, 
	Ciphertext<PolyType> queryValue
	){

	Ciphertext<PolyType> chainedBinaryXnorResult = do_chained_binary_xnor(cc, keyPair, ctext_vals_1, ctext_vals_2);


	Ciphertext<PolyType> res =  cc->EvalMult(chainedBinaryXnorResult, queryValue);

	return res;
}


/*
	Start with an encrypted 0, perform the chained binary xnor query against all keys, and add the result to the result.
	If theres a match you will be adding the value associated to the matching key, otherwise you add 0.
*/
Ciphertext<PolyType> do_query_all(
	CryptoContext<PolyType> cc,
	LPKeyPair<PolyType> keyPair,
	vector<vector<Ciphertext<PolyType>>> allDatabaseKeysBitwise,
	vector<Ciphertext<PolyType>> allDatabaseValues, // not bitwise
	vector<Ciphertext<PolyType>> queryKeyBitwise
	) {

	Ciphertext<PolyType> queryValueResult = encrypt_int(cc, keyPair, 0);

	for (unsigned int i = 0; i < allDatabaseKeysBitwise.size(); ++i)
	{

		vector<Ciphertext<PolyType>> databaseKey = allDatabaseKeysBitwise.at(i);
		Ciphertext<PolyType> databaseValue = allDatabaseValues.at(i);

		if(databaseKey.size() != queryKeyBitwise.size()){
			// MISMATCHED BIT LENGTH!!!!!
		}

		else{

			cout << "Searching.." << endl;

			Ciphertext<PolyType> singleKeyQueryResult = do_chained_binary_xnor_query(cc, keyPair, databaseKey, queryKeyBitwise, databaseValue);
			queryValueResult = cc->EvalAdd(queryValueResult, singleKeyQueryResult);
		}
	}


	return queryValueResult;
}



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






vector<Ciphertext<PolyType>> encryptBitwise(
	CryptoContext<PolyType> cc,
	LPKeyPair<PolyType> keyPair,
	uint32_t val
	){

	// cout << "encrypting bitwise" << endl;

	std::vector<uint32_t> bitwisePlaintext = convertToBits(val);

	vector<Ciphertext<PolyType>> thisBitwiseCtext = vector<Ciphertext<PolyType>>();
	for (unsigned int i = 0; i < bitwisePlaintext.size(); ++i)
	{
		// encrypt either a 1 or a 0. Perform a new encryption every time because this ensures a randomly generated noise distribution every time.
		if(bitwisePlaintext.at(i) == 1){
			thisBitwiseCtext.push_back(encrypt_int(cc, keyPair, 1));
		}
		else{
			thisBitwiseCtext.push_back(encrypt_int(cc, keyPair, 0));
		}
	}

	return thisBitwiseCtext;
}





/*
	Currently no standardized parameters for the SHIELD scheme when using PALISADE and so this function is used to set them.

	Returns the fully set CryptoContext ready for use.
*/
CryptoContext<PolyType> get_shield_crypto_context(){

	CryptoContext<PolyType> cc;

	// When decrypting this modulus is taken against the plaintext.
	int plaintextModulus = 1024;

	// this isn't used for the shield scheme. Only used for other schemes used in PALISADE.
	int depth = 4; 

	// The ciphertext polynomial order is half this value
	// Set lower in order to reduce computation time but reduce security level dramatically. 
	uint64_t cyclotomicOrder = 1024*2/16; 

	/// SOLINAS PRIME
	// BigInteger modulusBigInt = PolyType::Integer("2147352577");
	// BigInteger rootOfUnityBigInt = PolyType::Integer("1539779042");

	BigInteger modulusBigInt = PolyType::Integer("2147352577");
	BigInteger rootOfUnityBigInt = PolyType::Integer("461230749");

	// BigInteger modulusBigInt = PolyType::Integer("2147473409");
	// BigInteger rootOfUnityBigInt = PolyType::Integer("256290069");

	// related to base decomposition. Setting as 1 ensures base decomposition occurs for each bit.
	usint relinWindow = 1;

	// is the standard deviation of the random Gaussian and Normal distributions to generate keys and ciphertext noise(error factor).
	float stDev = 3;

	MODE mode = RLWE;

	try{

		shared_ptr<typename PolyType::Params> parms;

		parms.reset( new typename PolyType::Params(cyclotomicOrder,
								modulusBigInt,
								rootOfUnityBigInt));

		cc = CryptoContextFactory<PolyType>::genCryptoContextSHIELD(
			parms, plaintextModulus, relinWindow, stDev, mode, depth);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		return cc;

	} catch (const std::exception &e){
		std::cout << "Exception caught creating crypto context : " << e.what() << endl;
	}
		
	return NULL;
}


int main(int argc, char *argv[]) {


	
	/*
		This function call will provide the set of parameters to be used by the math and lattice layer backends.
	*/
	CryptoContext<PolyType> cc = get_shield_crypto_context();


	// these are the keys in database
	vector<uint32_t> databaseKeys = {1, 2,  3, 4,  5,  6, 7};

	// these are the associated values to the keys in the database
	vector<uint32_t> databaseValues = {7, 25, 3, 7 ,12, 15, 19};

	
	// the query value will the key at index 4 (which is the integer 5 resulting in a value of 12)
	uint32_t queryVal = databaseKeys.at(4);
	
	


	// contains both public and private keys which can be passed, and serialized, individually
	LPKeyPair<PolyType> keyPair;
	cout << "Generate public-private keypair" << endl;

	try{

		keyPair = cc->KeyGen();


		/* 	
			For the SHIELD scheme this does nothing right now. 
		 	It is however mandatory for most lattice based cryptography when performing chained multipliation operations.
		 	Therefore PALISADE makes it a mandatory operation to occur before calling EvalMult()
		*/
		cc->EvalMultKeyGen(keyPair.secretKey);



		// independently encrypt the key we want to extract the value for
		cout << "Encrypting query key : " << queryVal << endl << endl;
		vector<Ciphertext<PolyType>> bitwiseQueryValCText = encryptBitwise(cc, keyPair, queryVal);



		/*
			each key is stored as a value of encrypted bits

			vector<
				vector<ctext_bit_1, ctext_bit_2,..>,
				vector<ctext_bit_1, ctext_bit_2,..>,
				vector<ctext_bit_1, ctext_bit_2,..>
			>
		*/
		cout << "Encrypting all key value pairs." << endl << endl;

		cout << "Encrypting all keys first." << endl;

		vector<vector<Ciphertext<PolyType>>> allBitwiseCtext = vector<vector<Ciphertext<PolyType>>>();
		for (unsigned int i = 0; i < databaseKeys.size(); ++i)
		{
			cout << "Encrypting key from  key->value pair : (" << databaseKeys.at(i) << " : " << databaseValues.at(i) << ")" <<endl;
			allBitwiseCtext.push_back( encryptBitwise(cc, keyPair, databaseKeys.at(i)) );
		}


		/*
			Values are stored as whole integers (not bitwise)
		*/
		cout << endl << "Encrypting all values next." << endl;

		// cout << "enc vals to ctext" << endl;
		vector<Ciphertext<PolyType>> allEncryptedValsToExtract = vector<Ciphertext<PolyType>>();
		for (unsigned int i = 0; i < databaseValues.size(); ++i)
		{
			cout << "Encrypting value from  key->value pair : (" << databaseKeys.at(i) << " : " << databaseValues.at(i) << ")" <<endl;
			allEncryptedValsToExtract.push_back( encrypt_int(cc, keyPair, databaseValues.at(i)) );
		}



		/*
			Use the encrypted search key (bitwiseQueryValCText) and query the encrypted values.
		*/
		cout << endl << "Searching all encrypted key:value pairs for query key : "<< queryVal << endl << endl;

		Ciphertext<PolyType> queryResultValue = do_query_all(cc, keyPair, allBitwiseCtext, allEncryptedValsToExtract, bitwiseQueryValCText);

		Plaintext ptValue1;
		cc->Decrypt(keyPair.secretKey, queryResultValue, &ptValue1);

		cout << "Extracted database value : " << ptValue1 << endl;

		exit(1);

	}  catch (const std::exception &e){
		std::cout << "Exception caught while encrypting " << e.what() << endl;
		
	}

}


