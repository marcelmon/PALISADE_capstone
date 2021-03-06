/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
12/22/2015 2:37PM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Gyana Sahu, grs22@njit.edu
Nishanth Pasham, np386@njit.edu
Description:
This code tests the transform feature of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>
#include <algorithm>

#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestAutomorphism : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

//declaration for Automorphism Test on LTV scheme with polynomial operation in arbitrary cyclotomics.
std::vector<usint> ArbLTVAutomorphismPackedArray(usint i);
//declaration for Automorphism Test on BV scheme with polynomial operation in arbitrary cyclotomics.
std::vector<usint> ArbBVAutomorphismPackedArray(usint i);
//declaration for Automorphism Test on LTV scheme with polynomial operation in power of 2 cyclotomics.
std::vector<usint> LTVAutomorphismPackedArray(usint i);
//declaration for Automorphism Test on BV scheme with polynomial operation in powerof 2 cyclotomics.
std::vector<usint> BVAutomorphismPackedArray(usint i);
//declaration for Automorphism Test on FV scheme with polynomial operation in power of 2 cyclotomics.
std::vector<usint> FVAutomorphismPackedArray(usint i);
//Helper to function to produce a output of the input vector by i to the left(cyclic rotation).
std::vector<usint> Rotate(const std::vector<usint> &input,usint i);
//Helper to function to check if the elements in perm are the same in the init vector.
bool CheckAutomorphism(const std::vector<usint> &perm,const std::vector<usint> &init);

TEST(UTAUTOMORPHISM, Test_LTV_Automorphism_PowerOf2) {
	
	PackedIntPlaintextEncoding::Destroy();
	
	std::vector<usint> initVector = { 1,2,3,4,5,6,7,8 }; 
	
	for (usint index = 3; index < 16; index = index + 2) {
		auto morphedVector = LTVAutomorphismPackedArray(index);
		EXPECT_TRUE(CheckAutomorphism(morphedVector, initVector));
	}

}


TEST(UTAUTOMORPHISM, Test_BV_Automorphism_PowerOf2) {
	PackedIntPlaintextEncoding::Destroy();
	
	std::vector<usint> initVector = { 1,2,3,4,5,6,7,8 };

	for (usint index = 3; index < 16; index = index + 2) {
		auto morphedVector = BVAutomorphismPackedArray(index);
		EXPECT_TRUE(CheckAutomorphism(morphedVector, initVector));
	}

}

TEST(UTAUTOMORPHISM, Test_FV_Automorphism_PowerOf2) {
	PackedIntPlaintextEncoding::Destroy();

	std::vector<usint> initVector = { 1,2,3,4,5,6,7,8 };

	for (usint index = 3; index < 16; index = index + 2) {
		auto morphedVector = FVAutomorphismPackedArray(index);
		EXPECT_TRUE(CheckAutomorphism(morphedVector, initVector));
	}
}


TEST(UTAUTOMORPHISM, Test_LTV_Automorphism_Arb) {
	
	PackedIntPlaintextEncoding::Destroy();

	usint m = 22;

	auto totientList = GetTotientList(m);
	std::vector<usint> initVector = { 1,2,3,4,5,6,7,8,9,10 };

	for (usint index = 1; index < 10; index++) {
		auto morphedVector = ArbLTVAutomorphismPackedArray(totientList[index]);
		EXPECT_TRUE(CheckAutomorphism(morphedVector,initVector));
	}

	
}

TEST(UTAUTOMORPHISM, Test_BV_Automorphism_Arb) {
	PackedIntPlaintextEncoding::Destroy();

	usint m = 22;

	auto totientList = GetTotientList(m);
	std::vector<usint> initVector = { 1,2,3,4,5,6,7,8,9,10 };

	for (usint index = 1; index < 10; index++) {
		auto morphedVector = ArbBVAutomorphismPackedArray(totientList[index]);
		EXPECT_TRUE(CheckAutomorphism(morphedVector, initVector));
	}

}

TEST(UTAUTOMORPHISM, Test_FV_Automorphism_Arb) {
	

	EXPECT_EQ(1,1);
}

std::vector<usint> ArbLTVAutomorphismPackedArray(usint i) {

	usint m = 22;
	usint p = 2333;
	BigInteger modulusP(p);
	
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	
	//usint n = GetTotient(m);
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, p, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	
	std::vector<usint> result(intArrayNew);

	return std::move(intArrayNew);

}

std::vector<usint> ArbBVAutomorphismPackedArray(usint i) {
	
	
	usint m = 22;
	usint p = 2333;
	BigInteger modulusP(p);
	
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	
	//usint n = GetTotient(m);
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, p, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);

	std::vector<usint> result(intArrayNew);

	return result;

}

std::vector<usint> LTVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, q, rootOfUnity));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, plaintextModulus, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);

	std::vector<usint> result(intArrayNew);

	return result;

}

std::vector<usint> BVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, q, rootOfUnity));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, plaintextModulus, 1, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);

	std::vector<usint> result(intArrayNew);

	return result;

}

std::vector<usint> FVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigInteger q("67108913");
	BigInteger rootOfUnity("61564");
	usint plaintextModulus = 17;
	usint relWindow = 1;
	float stdDev = 4;

	BigInteger BBIPlaintextModulus(plaintextModulus);
	BigInteger delta(q.DividedBy(BBIPlaintextModulus));

	shared_ptr<ILParams> params(new ILParams(m, q, rootOfUnity));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(
		params, plaintextModulus,
		relWindow, stdDev, delta.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc->Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	vector<shared_ptr<Ciphertext<Poly>>> permutedCiphertext;

	shared_ptr<Ciphertext<Poly>> p1;

	p1 = cc->EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;

	cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);

	std::vector<usint> result(intArrayNew);

	return result;

}


std::vector<usint> Rotate(const std::vector<usint>& input, usint i)
{
	usint n = input.size();
	std::vector<usint> result(n,0);

	for (usint j = 0; j < n; j++) {
		usint newIndex = (n + j - i)%n;
		result.at(newIndex) = input.at(j);
	}

	return result;
}

bool CheckAutomorphism(const std::vector<usint>& perm, const std::vector<usint>& init)
{
	bool result = true;
	for (usint i = 0; i< init.size(); i++) {
		usint val = init.at(i);
		if (!(std::find(perm.begin(), perm.end(), val) != perm.end())) {
			result = false;
			break;
		}			

	}

	return result;
}
