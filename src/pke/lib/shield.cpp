/*
* @file shield.cpp - SHIELD scheme implementation.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */
/*
This code implements the SHIELD) homomorphic encryption scheme.
The scheme is described at 
The levelled Homomorphic scheme is described in

Implementation details are provided in


*/

#ifndef LBCRYPTO_CRYPTO_SHIELD_C
#define LBCRYPTO_CRYPTO_SHIELD_C

#include "shield.h"

#include <iostream>
using namespace std;


namespace lbcrypto {

	template <class Element>
	bool LPCryptoParametersSHIELD<Element>::Serialize(Serialized* serObj) const {
		if (!serObj->IsObject())
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);
		if (this->SerializeRLWE(serObj, cryptoParamsMap) == false)
			return false;
		cryptoParamsMap.AddMember("mode", std::to_string(m_mode), serObj->GetAllocator());

		serObj->AddMember("LPCryptoParametersSHIELD", cryptoParamsMap.Move(), serObj->GetAllocator());
		serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersSHIELD", serObj->GetAllocator());

		return true;
	}


	template <class Element>
	bool LPCryptoParametersSHIELD<Element>::Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersSHIELD");
		if (mIter == serObj.MemberEnd()) return false;

		if (this->DeserializeRLWE(mIter) == false) {
			return false;
		}

		SerialItem::ConstMemberIterator pIt;

		if ((pIt = mIter->value.FindMember("mode")) == serObj.MemberEnd()) {
			return false;
		}
		MODE mode = (MODE)atoi(pIt->value.GetString());

		this->SetMode(mode);

		return true;
	}

	/*
		
		t <- DRq,ok

		sk = s2x1 <- [1; -t]


		a <- Rq (uniform)
		e <- DRq,ok

		b = a*t + e

		pk = A1x2 = [b a]

	*/
	template <class Element>
	LPKeyPair<Element> LPAlgorithmSHIELD<Element>::KeyGen(CryptoContext<Element> cc, bool makeSparse)
	{


		LPKeyPair<Element>	kp(new LPPublicKeyImpl<Element>(cc), new LPPrivateKeyImpl<Element>(cc));

		const shared_ptr<LPCryptoParametersSHIELD<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersSHIELD<Element>>(cc->GetCryptoParameters());

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		typename Element::DugType dug;

		typename Element::TugType tug;



		const shared_ptr<LPCryptoParametersSHIELD<Element>> cryptoParamsForError = shared_ptr<LPCryptoParametersSHIELD<Element>>(cryptoParams);
		cryptoParamsForError->SetDistributionParameter(2);

		cout << "DIST PATTERN : 2 " << endl;
		const typename Element::DggType &dggForError = cryptoParamsForError->GetDiscreteGaussianGenerator();

		/*
			Demonstrates how the integer types are stored
		*/
		// BigInteger theFive("2147473409");


		// cout << "the five before " << theFive << endl;

		// cout << "the five msb before " << to_string(theFive.GetMSB()) << endl;

		// cout << "and bits from least to most ";
		// for (int i = 1; i <= theFive.GetMSB(); ++i)
		//  {
		//  	cout << to_string(theFive.GetBitAtIndex(i)) << " ";
		//  } 

		//  cout << endl;


		// theFive = theFive << 1;

		// cout << "the five after " << theFive << endl;

		// cout << "the five msb after " << to_string(theFive.GetMSB()) << endl;

		// cout << "and bits from least to most ";
		// for (int i = 1; i <= theFive.GetMSB(); ++i)
		//  {
		//  	cout << to_string(theFive.GetBitAtIndex(i)) << " ";
		//  } 

		//  cout << endl;

		// exit(1);













		/*
			Demonstrates how negatives are represented in Poly (as modulus - 1)
			Also demonstrates that GetBitAtIndex(1) is the least significant bit and GetBitAtIndex(l) is most significant
		*/
		// Element aRing(elementParams, COEFFICIENT, true);

		// aRing.SetValAtIndex(0, 1);
		// aRing.SetValAtIndex(1, elementParams->GetModulus() - 1);

		// cout << "Bit 1 for number  1 " << aRing.GetValAtIndex(0).GetBitAtIndex(1) << endl;
		// cout << "Bit 31 for number 1 " << aRing.GetValAtIndex(0).GetBitAtIndex(31) << endl;

		// int accumOne = 0;

		// cout << "Val at index 0 " << aRing.GetValAtIndex(0) << endl;
		// for (int i = 1; i <= 31; ++i)
		// {
		// 	cout << std::to_string(aRing.GetValAtIndex(0).GetBitAtIndex(i)) << " ";
		// 	accumOne += aRing.GetValAtIndex(0).GetBitAtIndex(i)<<(i - 1);
		// }
		// cout << "Accum one " << accumOne << endl;

		// cout << "Bit 1 for number -1 " << aRing.GetValAtIndex(1).GetBitAtIndex(1) << endl;
		// cout << "Bit 31 for number-1 " << aRing.GetValAtIndex(1).GetBitAtIndex(31) << endl;

		// int accumTwo = 0;

		// cout << "Val at index 1 " << aRing.GetValAtIndex(1) << endl;
		// for (int i = 1; i <= 31; ++i)
		// {
		// 	cout << std::to_string(aRing.GetValAtIndex(1).GetBitAtIndex(i)) << " ";
		// 	accumTwo += aRing.GetValAtIndex(1).GetBitAtIndex(i)<<(i - 1);
		// }
		// cout << "Accum two " << accumTwo << endl;

		// exit(1);





		/*
			Method to get root of unity in src/core/math/nbtheory.cpp
		*/

		// cout << " A ROOT OF UNITY " << endl;
		// cout << lbcrypto::RootOfUnity<BigInteger>(2*1024, 2147352577) << endl;

		// exit(1);










		// PROBABLY NEED THESE IN LPCryptoParametersSHIELD (because could be different but RLWE is only 1)
		// int sigmaK;
		// int sigmaCr;

		//Generate the secret key element (is [1, -t] , only the -t will be stored due to math type restrictions)
		Element t;

		// real secret key is [1, -t] but we store [-t] only
		// the secret key class uses 1 PolyType object for data (not a vector)
		if (cryptoParams->GetMode() == RLWE) 
			t = Element(dgg, elementParams, Format::COEFFICIENT);
		else
			t = Element(tug, elementParams, Format::COEFFICIENT);

		// cout << "THE T NO neg " << t << endl;


		
		// generate full public  key [Nx2]
		// public key in palisade is 1 dimensional vector of PolyType elements
		// shield will be 1 vector with N*2 elements 
		//
		//  N = 4
		//
		//		1 2
		//		3 4
		//		5 6
		//		7 8
		//
		//	is represented as vector:
		//
		//		1 2 3 4 5 6 7 8    
		//
			
		Element a(dug, elementParams, Format::COEFFICIENT);

		// Element e(dgg, elementParams, Format::COEFFICIENT);

		Element e(dggForError, elementParams, Format::COEFFICIENT);


		e.SwitchFormat(); // now EVALUATION

		a.SwitchFormat(); // now EVALUATION

		t.SwitchFormat(); // now EVALUATION

		Element aTimesT = a * t;

		
		
		

		

		Element b = aTimesT;

		// Element b = aTimesT + e;



		// secret key is [1; -t] but palisade only stores 1 value
		// for encryption will hardcode value for 1

		// IS ACTUALLY ZERO!!!
		Element zeroRing(elementParams, COEFFICIENT, true);
		zeroRing.SwitchFormat(); // now EVALUATION
		
		
		Element tNeg = zeroRing - t;



		kp.secretKey->SetPrivateElement(std::move(tNeg));


		// public key is [b a]
		kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
		kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

		return kp;
	}


/*

	u*BDI(Inxn) + Rnx1 * PK + e

*/
	template <class Element>
	Ciphertext<Element> LPAlgorithmSHIELD<Element>::Encrypt(const LPPublicKey<Element> publicKey,
		Element plaintext) const
	{

		/*
			Ciphertext Is NX2 Matrix

			1 2
			3 4
			5 6
			7 8

			is represented as vector in Palisade:

			1 2 3 4 5 6 7 8

		*/
		Ciphertext<Element> ciphertext(new CiphertextImpl<Element>(publicKey));

		const shared_ptr<LPCryptoParametersSHIELD<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersSHIELD<Element>>(publicKey->GetCryptoParameters());

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		// const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();


		const shared_ptr<LPCryptoParametersSHIELD<Element>> cryptoParamsForError = shared_ptr<LPCryptoParametersSHIELD<Element>>(cryptoParams);
		cryptoParamsForError->SetDistributionParameter(2);

		const typename Element::DggType &dggForError = cryptoParamsForError->GetDiscreteGaussianGenerator();



		// Element plaintext(ptxt, elementParams);
		plaintext.SwitchFormat(); // switch to evaluation format

		
		typename Element::Integer theModulus =  elementParams->GetModulus();

		int l = theModulus.GetMSB(); // equivalent to ceil(log[modulus])

		int N = 2*l; // ciphertext height (width will be 2)


		// ciphertext is NX2 matrix of Element
		// if (doEncryption) {


			if(!std::is_same<Element, Poly>::value){
				cout << "IS NOT RIGHT TEMPLATE OH NOES!" << endl;
				exit(1);
			}




			/*
				Generate BDIMatrix
			*/
			Matrix<Element> BDIMatrix = Matrix<Element>(
				[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
				N, 
				2
				);

			


			// Matrix<Element> BDIMatrixIDENT = Matrix<Element>(
			// 	[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
			// 	N, 
			// 	N
			// 	);

			// BDIMatrixIDENT.Identity();

			Element onePoly(elementParams, COEFFICIENT, true);
			onePoly.at(0) = typename Element::Integer(1);
			onePoly.SetFormat(EVALUATION);

			// generates array of l polys with only first coefficients set
			// set to 1, 2, 4, 8, ..., 2^(l-1)
			std::vector<Element> base2Out = onePoly.PowersOfBase(1);

			Element zeroElement(elementParams, EVALUATION, true);

			for (int i = 0; i < N; ++i)
			{
				if(i < N/2){
					BDIMatrix(i, 0) = base2Out.at(i).Clone();
					BDIMatrix(i, 1) = zeroElement.Clone();
				}
				else{
					BDIMatrix(i, 0) = zeroElement.Clone();
					BDIMatrix(i, 1) = base2Out.at(i - N/2).Clone();
				}
			}



			/*
				Generate rand 1s matrix
			*/
			Matrix<Element> randCoefficientPolyMatrix = Matrix<Element>(
				[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
				N, 
				1
				);

			
			for (int i = 0; i < N; ++i)
			{
				// // this is where to generate the rNx1 {0,1} and multiply into each row
				// // true for initialize to 0s
				Element randCoefficientPoly(cryptoParams->GetElementParams(), COEFFICIENT, true);

				for (unsigned int j = 0; j < cryptoParams->GetElementParams()->GetRingDimension(); ++j) {
					randCoefficientPoly.at(j) = typename Element::Integer(rand()%2);
				}
				randCoefficientPoly.SwitchFormat();

				randCoefficientPolyMatrix(i, 0) = std::move(randCoefficientPoly);

			}

			/*
				Unpack public key from vector into matrix
			*/
			Matrix<Element> publicKeyElementMatrix = Matrix<Element>(
				[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
				1, 
				2
				);

			// publicKey : [b a]
			publicKeyElementMatrix(0,0) = publicKey->GetPublicElements().at(0); // b
			publicKeyElementMatrix(0,1) = publicKey->GetPublicElements().at(1); // a



			/*
				Generate an error matrix Nx2
			*/
			// error is a distributed gaussian sampled for all Nx2 elements
			// Matrix<Element> errorMatrix = Matrix<Element>(
			// 	[elementParams, dgg]() { return make_unique<Element> (dgg, elementParams, Format::EVALUATION); },
			// 	N, 
			// 	2
			// 	);

			Matrix<Element> errorMatrix = Matrix<Element>(
				[elementParams, dggForError]() { return make_unique<Element> (dggForError, elementParams, Format::EVALUATION); },
				N, 
				2
				);


			/*
				Generate the ciphertext
			*/
			// Matrix<Element> ciphertextMatrix = (plaintext * BDIMatrix) + (randCoefficientPolyMatrix * publicKeyElementMatrix) + errorMatrix;

			Matrix<Element> ciphertextMatrix = (plaintext * BDIMatrix) + (randCoefficientPolyMatrix * publicKeyElementMatrix);


			/*
				Pack ciphertext matrix into the expected vector format
				Do: 

					1 2
					3 4 
					5 6
					7 8

					into 

					1 2 3 4 5 6 7 8 
	
			*/
			std::vector<Element> ciphertextVector;

			for (int i = 0; i < N; ++i)
			{
				ciphertextVector.push_back(std::move(ciphertextMatrix(i,0)));
				ciphertextVector.push_back(std::move(ciphertextMatrix(i,1)));
			}

			ciphertext->SetElements(std::move(ciphertextVector));

			return ciphertext;

		// }
		// else
		// {

		// }

		// return ciphertext;
	}


	template <class Element>
	Ciphertext<Element> LPAlgorithmSHIELD<Element>::Encrypt(const LPPrivateKey<Element> privateKey,
		Element ptxt) const
	{
		return NULL;
	}

	template <class Element>
	DecryptResult LPAlgorithmSHIELD<Element>::Decrypt(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext,
		NativePoly *plaintext) const
	{
		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();

		const std::vector<Element> &ciphertextElements = ciphertext->GetElements();

		const Element &privK = privateKey->GetPrivateElement();

		// Cnx2 * s2x1  (C == ciphertext lattice, s == secret key > privK) << fill in a 1 for first element in secret key

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		// Poly plaintextElement(privateKey->GetCryptoParameters()->GetElementParams(), COEFFICIENT, true);


		typename Element::Integer theModulus =  privateKey->GetCryptoParameters()->GetElementParams()->GetModulus();
		
		// # bits of security 
		int l = theModulus.GetMSB();  // bit # starts at 1

		// ciphertext height (width=2)
		int N = 2*l;
		/*
			ciphertextElements:

				0 1
				2 3
				4 5

			as  0 1 2 3 4 5 ...

			privK : // only t values are stored
				1
				-t
		*/

		if(!std::is_same<Element, Poly>::value){
			cout << "IS NOT RIGHT TEMPLATE OH NOES!" << endl;
			exit(1);
		}


		/*
			Unpack private key (stored only -t)  into matrix of [1; -t]

		*/
		Matrix<Element> privKeyMatrix = Matrix<Element>(
			[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
			2, 
			1
			);

		Element onePoly(elementParams, COEFFICIENT, true); 		
		onePoly.at(0) =  typename Element::Integer(1);
		onePoly.SwitchFormat();

		privKeyMatrix(0, 0) = onePoly;
		privKeyMatrix(1, 0) = privK;
		

		

		/*
			Unpack ciphertext vector into Matrix

			Do: 
				1 2 3 4 5 6 7 8 

				into

				1 2
				3 4 
				5 6
				7 8
		
		*/
		Matrix<Element> cipherTextElementsMatrix = Matrix<Element>(
			[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
			N, 
			2
			);

		for (int i = 0; i < N; ++i)
		{
			cipherTextElementsMatrix(i, 0) = ciphertextElements[i * 2];
			cipherTextElementsMatrix(i, 1) = ciphertextElements[(i * 2 + 1)];
		}


		/*
			Perform CNx2 * s2x1
		*/
		Matrix<Element> decryptMultiplyResultsMatrix = Matrix<Element>(
			[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
			N, 
			1
			);

		decryptMultiplyResultsMatrix = cipherTextElementsMatrix * privKeyMatrix;




		typename Element::Integer averagingSum("214735257777777777777777");


		averagingSum = 0;
		decryptMultiplyResultsMatrix(0, 0).SetFormat(COEFFICIENT);

		int counter = 0;
		for (int j = 0; j < l; ++j)
		{
			// for (unsigned int i = 1; i < cryptoParams->GetElementParams()->GetRingDimension(); ++i)
			for (int i = 1; i < l; ++i)
			{
				decryptMultiplyResultsMatrix(j, 0).SetFormat(COEFFICIENT);
				averagingSum += decryptMultiplyResultsMatrix(j, 0).at(i);
				counter++;
			}
		}
			

		// cout << "AVERGING SUM : " << averagingSum << endl;

		typename Element::Integer finalAverage(averagingSum/counter);

		// cout << "FINAL AVERAGE NOISE : " << finalAverage << endl;




		/*
			Top row ONLY
		*/

		// cout << "TOP ROW POLY " << endl;
		// for (int i = 0; i < l; ++i)
		// {
		// 	for (int j = 0; j < l; ++j)
		// 	{


		// 		typename Element::Integer theBit = decryptMultiplyResultsMatrix(0, 0).GetValAtIndex(j).GetBitAtIndex(l - i);

		// 		// typename Element::Integer theBit = decryptMultiplyResultsMatrix(0, 0).GetValAtIndex(l - i - 1).GetBitAtIndex(j + 1);
		// 		cout << theBit << " ";

		// 		continue;

		// 	}
		// 	cout << endl;
		// }

		// cout << endl << endl;


		// cout << " FIRST POLY COEFFICIENT TOP ROW " << endl;
		// for (int i = 0; i < l; ++i)
		// {

		// 	typename Element::Integer theBit = decryptMultiplyResultsMatrix(0, 0).GetValAtIndex(0).GetBitAtIndex(l - i);

		// 	cout << theBit << " ";	
			
		// }

		// cout << endl << endl;


		// cout << "BEFORE REMOVING NOISE" << endl;


		// /*
		// 	Build resultant poly from most significant bits of first l elements

		// 	The bits at element i=l-1 are the least significant, so the amount to add is  1 for each coefficient
		// 	The amount to add at position i=0 is 1*2^(l-1)
		// */
		// Poly finalPlaintextBeforeRemovingNoise(privateKey->GetCryptoParameters()->GetElementParams(), COEFFICIENT, true);


		// for (int i = 0; i < N/2; ++i)
		// {

		// 	decryptMultiplyResultsMatrix(i, 0).SetFormat(COEFFICIENT);
			
		// 	for (int j = 0; j < l; ++j)
		// 	{

		// 		typename Element::Integer theBit = decryptMultiplyResultsMatrix(i, 0).GetValAtIndex(j).GetBitAtIndex(l);
		// 		cout << theBit << " ";
				

		// 		if(theBit > 0){
		// 			typename Element::Integer currentPolyCoefficient = finalPlaintext.GetValAtIndex(j);

		// 			finalPlaintextBeforeRemovingNoise.SetValAtIndex(j, currentPolyCoefficient +  (1 << (l - i - 1)));


		// 		}

		// 		continue;

		// 	}
		// 	cout << endl;
		// }

		// cout << endl << endl;

		// *plaintext = finalPlaintextBeforeRemovingNoise;

		// return DecryptResult(plaintext->GetLength());


		for (int i = 0; i < N/2; ++i)
		{
			decryptMultiplyResultsMatrix(i, 0).SetFormat(COEFFICIENT);

			// decryptMultiplyResultsMatrix(i, 0) -= (theModulus - (finalAverage + 1));

			// decryptMultiplyResultsMatrix(i, 0) -= (theModulus - (finalAverage));

			// decryptMultiplyResultsMatrix(i, 0) -= (theModulus - (finalAverage - 1));



			// decryptMultiplyResultsMatrix(i, 0) -= (theModulus + (finalAverage + 1)); // <<<<

			// decryptMultiplyResultsMatrix(i, 0) -= (theModulus + (finalAverage)); // <<<<

			// decryptMultiplyResultsMatrix(i, 0) -= (theModulus + (finalAverage - 1)); // <<<<<



			// decryptMultiplyResultsMatrix(i, 0) += (theModulus - (finalAverage + 1));

			// decryptMultiplyResultsMatrix(i, 0) += (theModulus - (finalAverage));

			// decryptMultiplyResultsMatrix(i, 0) += (theModulus - (finalAverage - 1));




			// decryptMultiplyResultsMatrix(i, 0) += (theModulus + (finalAverage + 1));

			// decryptMultiplyResultsMatrix(i, 0) += (theModulus + (finalAverage));

			// decryptMultiplyResultsMatrix(i, 0) += (theModulus + (finalAverage - 1));




			// decryptMultiplyResultsMatrix(i, 0) -= (finalAverage + 1);

			// decryptMultiplyResultsMatrix(i, 0) -= (finalAverage);

			// decryptMultiplyResultsMatrix(i, 0) -= (finalAverage - 1); // <<<<< <<<< THIS ONEEEEEE


			// decryptMultiplyResultsMatrix(i, 0) += (finalAverage + 1);

			// decryptMultiplyResultsMatrix(i, 0) += (finalAverage);

			// decryptMultiplyResultsMatrix(i, 0) += (finalAverage - 1);

		}
		/*
			Build resultant poly from most significant bits of first l elements

			The bits at element i=l-1 are the least significant, so the amount to add is  1 for each coefficient
			The amount to add at position i=0 is 1*2^(l-1)
		*/
		Element finalPlaintext(privateKey->GetCryptoParameters()->GetElementParams(), COEFFICIENT, true);

		for (int i = 0; i < N/2; ++i)
		{

			decryptMultiplyResultsMatrix(i, 0).SetFormat(COEFFICIENT);
			
			for (int j = 0; j < l; ++j)
			{
				// if(j >= 5){
				// 	break;
				// }
				

				typename Element::Integer theBit = decryptMultiplyResultsMatrix(i, 0).at(j).GetBitAtIndex(l);


				// if(theBit == 1){
				// 	cout << "0 ";
				// }
				// else{
				// 	cout << "1 ";
				// }
				// cout << theBit << " ";


				if(theBit > 0){
					typename Element::Integer currentPolyCoefficient = finalPlaintext.at(j);

					finalPlaintext.at(j) = currentPolyCoefficient +  (1 << (l - i - 1));


				}
				
				continue;

			}
			// cout << endl;
		}


		// cout << finalPlaintext << endl << "final pt" << endl;

		// exit(1);

		*plaintext = finalPlaintext.DecryptionCRTInterpolate(cryptoParams->GetPlaintextModulus());

		return DecryptResult(plaintext->GetLength());

	}

	/*
		Add each element of both ciphertexts together

		c1 + c2
	*/
	template <class Element>
	Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalAdd(const Ciphertext<Element> ciphertext1,

	    const Ciphertext<Element> ciphertext2) const {

	    if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
	        std::string errMsg = "LPAlgorithmSHESHIELD::EvalAdd crypto parameters are not the same";
	        throw std::runtime_error(errMsg);
	    }

	    Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext1));

	    const std::vector<Element> &cipherText1Elements = ciphertext1->GetElements();
	    const std::vector<Element> &cipherText2Elements = ciphertext2->GetElements();
	    std::vector<Element> finalElements;

	    for (unsigned int i = 0; i < cipherText2Elements.size(); i++) {
	        finalElements.push_back(cipherText1Elements[i] + cipherText2Elements[i]);
	    }

	    newCiphertext->SetElements(std::move(finalElements));

	    return newCiphertext;

	}



template <class Element>
Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalAdd(
	const Ciphertext<Element> ciphertext,
	const Plaintext plaintext) const
{
	return NULL;
}



	template <class Element>
	Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalSub(
		const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2) const {

	    if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
	        std::string errMsg = "LPAlgorithmSHESHIELD::EvalAdd crypto parameters are not the same";
	        throw std::runtime_error(errMsg);
	    }

	     Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext1));
	    const std::vector<Element> &cipherText1Elements = ciphertext1->GetElements();
	    const std::vector<Element> &cipherText2Elements = ciphertext2->GetElements();
	    std::vector<Element> finalElements;

	    for (unsigned int i = 0; i < cipherText2Elements.size(); i++) {
	        finalElements.push_back(cipherText1Elements[i] - cipherText2Elements[i]);
	    }

	    newCiphertext->SetElements(std::move(finalElements));

	    return newCiphertext;
	}

template <class Element>
Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalSub(
	const Ciphertext<Element> ciphertext,
	const Plaintext plaintext) const
{
	return NULL;
}

	/*
		BD(c1) * c2
	*/
	template <class Element>
	Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalMult(
		const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2) const
	{

		if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
			throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
		}


		// double startTimeMult = currentDateTime();

		const shared_ptr<LPCryptoParametersSHIELD<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersSHIELD<Element>>(ciphertext1->GetCryptoParameters());

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		
		typename Element::Integer theModulus =  elementParams->GetModulus();

		int l = theModulus.GetMSB(); // equivalent to ceil(log[modulus])


		int N = 2*l; // ciphertext height (width will be 2)

		
		usint relinWindow = cryptoParams->GetRelinWindow();
		Ciphertext<Element> newCiphertext(new CiphertextImpl<Element>(*ciphertext1));



		/* 
		are in form
			1 2
			3 4
			5 6
			7 8
		*/
		const std::vector<Element> &c1 = ciphertext1->GetElements();

		const std::vector<Element> &c2 = ciphertext2->GetElements();


		// cout << "going in N " << N << endl;


		if(!std::is_same<Element, Poly>::value){
			cout << "IS NOT RIGHT TEMPLATE OH NOES!" << endl;
			exit(1);
		}






		// double MANUALbaseDecomposeStartTime = currentDateTime();

		// Matrix<Element> c1MatrixWithBaseDecomposeManual = Matrix<Element>(
		// 	[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
		// 	N, 
		// 	N
		// 	);
		
		// std::vector<Element> c1Coefficient = std::vector<Element>();


		// for(unsigned int i = 0; i < c1.size(); ++i)
		// {
		// 	Element coeficientRepresentation = Element(c1.at(i));
		// 	coeficientRepresentation.SetFormat(COEFFICIENT);
		// 	c1Coefficient.push_back(std::move(coeficientRepresentation));
		// }

		// unsigned int ringDim = cryptoParams->GetElementParams()->GetRingDimension();

		// auto bitDecomposedCoefficientRowC1 = [c1, l, ringDim, elementParams](int position) -> std::vector<Element> { 
		// 	std::vector<Element> newRow = vector<Element>();
		// 	Element forCoef = Element(c1.at(position));
		// 	forCoef.SetFormat(COEFFICIENT);
			
		// 	int theBit;

		// 	Element newElement;

		// 	for (int j = 1; j <= l; ++j) // go through each bit
		// 	{
		// 		newElement = Element(elementParams, COEFFICIENT, true);
		// 		for (unsigned int k = 0; k < ringDim; ++k) { // go through each ring coefficient
		// 			theBit = forCoef.GetValAtIndex(k).GetBitAtIndex(j);
		// 			if(theBit > 0){
		// 				newElement.SetValAtIndex(k, 1 << (j-1));
		// 			}
		// 		}
		// 		newElement.SetFormat(EVALUATION);
		// 		newRow.push_back(std::move(newElement));
		// 	}

		// 	return newRow;
		// };


		// Element forCoef;
		// Element newElement;

		// for (int i = 0; i < N; ++i)
		// {

		// 	forCoef = Element(c1.at(i * 2));
		// 	forCoef.SwitchFormat();

		// 	for (int j = 1; j <= l; ++j)
		// 	{

		// 		newElement = Element(elementParams, COEFFICIENT, true);
		// 		for (unsigned int k = 0; k < cryptoParams->GetElementParams()->GetRingDimension(); ++k)
		// 		{
		// 			if(forCoef.GetValAtIndex(k).GetBitAtIndex(j) != 0){
		// 				newElement.SetValAtIndex(k, 1 << (j-1));
		// 			}
		// 		}
		// 		newElement.SetFormat(EVALUATION);
		// 		c1MatrixWithBaseDecomposeManual(i, j - 1) = std::move(newElement);

		// 		// c1MatrixWithBaseDecomposeManual(i, j - 1) = std::move(newRow.at(j-1));
		// 		// c1MatrixWithBaseDecomposeManual(i, j + l - 1) = std::move(newRow2.at(j-1));
		// 	}

		// 	forCoef = Element(c1.at((i * 2) + 1));
		// 	forCoef.SwitchFormat();

		// 	for (int j = 1; j <= l; ++j)
		// 	{
		// 		newElement = Element(elementParams, COEFFICIENT, true);
		// 		for (unsigned int k = 0; k < cryptoParams->GetElementParams()->GetRingDimension(); ++k)
		// 		{
		// 			if(forCoef.GetValAtIndex(k).GetBitAtIndex(j) != 0){
		// 				newElement.SetValAtIndex(k, 1 << (j-1));
		// 			}
		// 		}
		// 		newElement.SetFormat(EVALUATION);
		// 		c1MatrixWithBaseDecomposeManual(i, j + l - 1) = std::move(newElement);
		// 	}
		// }

		// double MANUALbaseDecomposeTotalTime = currentDateTime() - MANUALbaseDecomposeStartTime;



		/*
			Unpack each element of c1 into matrix and perform base decomposition at the same time
		*/
		Matrix<Element> c1MatrixWithBaseDecompose = Matrix<Element>(
			[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
			N, 
			N
			);

		


		// std::vector<double> allBaseDecomposeTimes;


		// double baseDecomposeStartTime = currentDateTime();
		for (int i = 0; i < N; ++i)
		{	
			// double startTimeBaseDecompose = currentDateTime();

			// base decompose will automatically inverse NTT to coefficient then return in eval mode (as true is passed)
			std::vector<Element> baseDecomposeLeft = std::move(c1.at(i*2).BaseDecompose(relinWindow, true));

			// allBaseDecomposeTimes.push_back(currentDateTime() - startTimeBaseDecompose);

			for (size_t j = 0; j < baseDecomposeLeft.size(); ++j)
			{
				c1MatrixWithBaseDecompose(i, j) =  std::move(baseDecomposeLeft.at(j));
			}


			// startTimeBaseDecompose = currentDateTime();

			// base decompose will automatically inverse NTT to coefficient then return in eval mode (as true is passed)
			std::vector<Element> baseDecomposeRight = std::move(c1.at(i*2 + 1).BaseDecompose(relinWindow, true));

			// allBaseDecomposeTimes.push_back(currentDateTime() - startTimeBaseDecompose);

			for (size_t j = 0; j < baseDecomposeRight.size(); ++j)
			{
				c1MatrixWithBaseDecompose(i, baseDecomposeLeft.size() + j) = std::move(baseDecomposeRight.at(j)); 
			}
		}

		// double baseDecomposeTotalTime = currentDateTime() - baseDecomposeStartTime;

		/*
			Unpack c2 vector into matrix
		*/
		Matrix<Element> c2Matrix = Matrix<Element>(
			[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
			N, 
			2
			);

		// double unpackC2StartTime = currentDateTime();
		for (int i = 0; i < N; ++i)
		{
			c2Matrix(i, 0) = c2.at(i * 2);
			c2Matrix(i, 1) = c2.at((i*2) + 1);
		}
		// double unpackC2TotalTime = currentDateTime() - unpackC2StartTime;


		/*
			Perform matrix mult
		*/

		// double manualMatrixMultStartTime = currentDateTime();

		// double manualMatrixMultCREATEStartTime = currentDateTime();
		// Matrix<Element> result = Matrix<Element>(
		// 	[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
		// 	N, 
		// 	2
		// 	);
		// double manualMatrixMultCREATETotalTime = currentDateTime() - manualMatrixMultCREATEStartTime;

		// for (int row = 0; row < N; ++row) { // N rows in first matrix
		// 	for (int i = 0; i < N; ++i) { // N cols in first matrix (bit decompose matrix)
		// 		for (int col = 0; col < 2; ++col) {
		// 			result(row,col) += c1MatrixWithBaseDecompose(row, i) * c2Matrix(i, col);
		// 	    }
		// 	}
	 //    }

	 //    double manualMatrixMultTotalTime = currentDateTime() - manualMatrixMultStartTime;



		// double matrixMultStartTime = currentDateTime();
		Matrix<Element> finalMatrixMult = c1MatrixWithBaseDecompose * c2Matrix;
		// double matrixMulttotalTime = currentDateTime() - matrixMultStartTime;

		// pack resultant matrix into expected vector

		// double repackMatrixStartTime = currentDateTime();
		std::vector<Element> multResult;
		for (int i = 0; i < N; ++i)
		{
			multResult.push_back(std::move(finalMatrixMult(i, 0)));
			multResult.push_back(std::move(finalMatrixMult(i, 1)));
		}

		newCiphertext->SetElements(std::move(multResult));
		// double repackMatrixTotalTime = currentDateTime() - repackMatrixStartTime;

		// double endTimeMult = currentDateTime() - startTimeMult;
	
		// cout << "TOTAL MULT TIME : " << endTimeMult << endl;

		// double totalBaseDecomposeTime = 0;
		// for (unsigned int i = 0; i < allBaseDecomposeTimes.size(); ++i)
		// {
		// 	totalBaseDecomposeTime += allBaseDecomposeTimes.at(i);
		// }
		
		// cout << "TOTAL BASE DECOMPOSE TIME : " << totalBaseDecomposeTime << endl;

		// cout << "TOTAL BASE DECOMPOSE LOOP TIME : " << baseDecomposeTotalTime << endl;

		// cout << "Total unpack c2 time : " << unpackC2TotalTime << endl;

		// cout << "Total matrix mult time : " << matrixMulttotalTime << endl;

		// cout << "Total matrix repack time : " << repackMatrixTotalTime << endl;

		// cout << "TOTAL MANUAL BIT BECOMPOSE TIME : " << MANUALbaseDecomposeTotalTime << endl;

		// cout << "Total MANUAL matrix mult time : " << manualMatrixMultTotalTime << endl;

		// cout << "Total MANUAL matrix mult CREATE time : " << manualMatrixMultCREATETotalTime << endl;

		
		// cout << endl;

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalMult(
		const Ciphertext<Element> ciphertext,
		const Plaintext plaintext) const
	{

		return NULL;
	}


	template <class Element>
	Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalMult(const Ciphertext<Element> ciphertext1,
		const Ciphertext<Element> ciphertext2, const LPEvalKey<Element> ek) const {

		Ciphertext<Element> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

		// return this->KeySwitch(ek, newCiphertext);

		return newCiphertext;

	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalNegate(const Ciphertext<Element> ciphertext) const {

		return NULL;
	}


	template <class Element>
	LPEvalKey<Element> LPAlgorithmSHESHIELD<Element>::KeySwitchGen(const LPPrivateKey<Element> originalPrivateKey, const LPPrivateKey<Element> newPrivateKey) const {

		return NULL;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::KeySwitch(const LPEvalKey<Element> keySwitchHint, const Ciphertext<Element> cipherText) const {

		return NULL;
	}

	template <class Element>
	LPEvalKey<Element> LPAlgorithmSHESHIELD<Element>::EvalMultKeyGen(const LPPrivateKey<Element> originalPrivateKey) const
	{


		LPEvalKey<Element> keySwitchHintRelin(new LPEvalKeyRelinImpl<Element>(originalPrivateKey->GetCryptoContext()));

		return keySwitchHintRelin;
	}

	template <class Element>
	Ciphertext<Element> LPAlgorithmSHESHIELD<Element>::EvalAutomorphism(const Ciphertext<Element> ciphertext, usint i,
		const std::map<usint, LPEvalKey<Element>> &evalKeys) const
	{

		return NULL;

	}

	template <class Element>
	shared_ptr<std::map<usint, LPEvalKey<Element>>> LPAlgorithmSHESHIELD<Element>::EvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
		const std::vector<usint> &indexList) const
	{

		return NULL;

	}

	template <class Element>
	LPEvalKey<Element> LPAlgorithmPRESHIELD<Element>::ReKeyGen(const LPPrivateKey<Element> newSK,
		const LPPrivateKey<Element> origPrivateKey) const
	{

		return NULL;
	}

	//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
	template <class Element>
	Ciphertext<Element> LPAlgorithmPRESHIELD<Element>::ReEncrypt(const LPEvalKey<Element> EK,
		const Ciphertext<Element> ciphertext) const
	{

		return NULL;

	}

	template <class Element>
	Ciphertext<Element> LPLeveledSHEAlgorithmSHIELD<Element>::ModReduce(Ciphertext<Element> cipherText) const {

		return NULL;
	}



template <class Element>
Ciphertext<Element> LPAlgorithmMultipartySHIELD<Element>::MultipartyDecryptLead(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext) const
{

	return NULL;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartySHIELD<Element>::MultipartyDecryptMain(const LPPrivateKey<Element> privateKey,
		const Ciphertext<Element> ciphertext) const
{

	return NULL;
}


template <class Element>
DecryptResult LPAlgorithmMultipartySHIELD<Element>::MultipartyDecryptFusion(const vector<Ciphertext<Element>>& ciphertextVec,
		NativePoly *plaintext) const
{

	return DecryptResult();

}

	// Enable for LPPublicKeyEncryptionSchemeSHIELD
	template <class Element>
	void LPPublicKeyEncryptionSchemeSHIELD<Element>::Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPAlgorithmSHIELD<Element>();
			break;
		case PRE:
			throw std::logic_error("PRE feature not supported for SHIELD scheme");
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE = new LPAlgorithmPRESHIELD<Element>();
			break;
		case SHE:
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE = new LPAlgorithmSHESHIELD<Element>();
			break;
		case LEVELEDSHE:
			throw std::logic_error("LEVELEDSHE feature not supported for SHIELD scheme");
			if (this->m_algorithmLeveledSHE == NULL)
				this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmSHIELD<Element>();
			break;
		case MULTIPARTY:
			throw std::logic_error("MULTIPARTY feature not supported for SHIELD scheme");
			if (this->m_algorithmMultiparty == NULL)
				this->m_algorithmMultiparty = new LPAlgorithmMultipartySHIELD<Element>();
			break;
		case FHE:
			throw std::logic_error("FHE feature not supported for SHIELD scheme");
		}
	}

}  // namespace lbcrypto ends

#endif
