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

// static function<unique_ptr<Poly>()> generateRandOnesPoly(ElemParams elementParams) {

//     Poly randOnes = Poly(elementParams, COEFFICIENT, true); 
// 	for (unsigned int j = 0; j < elementParams->GetRingDimension(); ++j) {
// 		randOnes.SetValAtIndex(j, rand()%2);
// 		// randOnes.SwitchFormat();
// 		return randOnes;
// 	}	
// }


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
	LPKeyPair<Element> LPAlgorithmSHIELD<Element>::KeyGen(CryptoContext<Element>* cc, bool makeSparse)
	{


	


		LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));

		const shared_ptr<LPCryptoParametersSHIELD<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersSHIELD<Element>>(cc->GetCryptoParameters());

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		typename Element::DugType dug;

		typename Element::TugType tug;


		// Matrix<Element> BDIMatrix = Matrix<Element>(
		// 		[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
		// 		62, 
		// 		2
		// 		);


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













		// cout << lbcrypto::RootOfUnity<BigInteger>(2*1024, elementParams->GetModulus()) << endl;

		// exit(1);


		// Element testingRingOnes(elementParams, COEFFICIENT, true);

		// testingRingOnes.SetValAtIndex(0, 1);
		// testingRingOnes.SetValAtIndex(1, 2);
		// testingRingOnes.SetValAtIndex(2, 3);

		// Element testingRingATwo(elementParams, COEFFICIENT, true);

		// testingRingATwo.SetValAtIndex(0, 4);
		// testingRingATwo.SetValAtIndex(1, 5);
		// testingRingATwo.SetValAtIndex(2, 6);

		// cout << testingRingOnes << endl << testingRingATwo << endl;

		// testingRingOnes.SwitchFormat();
		// testingRingATwo.SwitchFormat();

		// Element res = testingRingOnes + testingRingATwo;
		// res.SwitchFormat();
		// cout << res << endl;
		// exit(1);

		

		// testingRingATwo.SetValAtIndex(0, elementParams->GetModulus() - 2);

		// cout << "A ones " << testingRingOnes << endl;
		// cout << "A twos " << testingRingATwo << endl;
		// testingRingOnes.SwitchFormat();
		// testingRingATwo.SwitchFormat();

		// Element res = testingRingOnes * testingRingATwo;
		// res.SwitchFormat();
		// cout << res << endl;
		// exit(1);











		// PROBABLY NEED THESE
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

		cout << "THE T NO neg " << t << endl;

		


		// cout << "THE T is neg " << t << endl;
		// exit(1);

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

		Element e(dgg, elementParams, Format::COEFFICIENT);


		
		e.SwitchFormat(); // now EVALUATION

		a.SwitchFormat(); // now EVALUATION

		t.SwitchFormat(); // now EVALUATION

		Element aTimesT = a * t;

		
		
		

		// Element b = aTimesT + e;

		Element b = aTimesT;



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
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHIELD<Element>::Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
		Poly &ptxt, bool doEncryption) const
	{

		/*
			Is NX2

			1 2
			3 4
			5 6
			7 8

			is represented as vector:

			1 2 3 4 5 6 7 8

		*/
		shared_ptr<Ciphertext<Element>> ciphertext(new Ciphertext<Element>(publicKey->GetCryptoContext()));

		const shared_ptr<LPCryptoParametersSHIELD<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersSHIELD<Element>>(publicKey->GetCryptoParameters());

		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		// Ternary uniform generator (not used here)
			// typename Element::TugType tug;

		Element plaintext(ptxt, elementParams);
		plaintext.SwitchFormat(); // switch to evaluation format

		
		typename Element::Integer theModulus =  elementParams->GetModulus();

		int l = theModulus.GetMSB(); // equivalent to ceil(log[modulus])
		
		int N = 2*l; // ciphertext height (width will be 2)

		// ciphertext is NX2 matrix of Element





		// shared_ptr<ILParams> copyILParams; // this type is needed in order to use Poly::MakeDiscreteUniformAllocator and Poly::MakeDiscreteGaussianCoefficientAllocator (as opposed to templated type)


		// // need to access each paramater individually because we need to convert typename Element::Params into ILParams
		// copyILParams.reset( 
		// 	new ILParams(
		// 		elementParams->GetCyclotomicOrder(), // Cyclotomic Order (2 * ring dimension)
		// 		elementParams->GetModulus(), 
		// 		elementParams->GetRootOfUnity()
		// 		)
		// 	);

		// auto dugAllocator = Poly::MakeDiscreteUniformAllocator(
		// 	copyILParams,
		// 	EVALUATION
		// );

		// auto dggAllocator = Poly::MakeDiscreteGaussianCoefficientAllocator(
		// 	copyILParams,
		// 	EVALUATION,
		// 	cryptoParams->GetDistributionParameter()
		// );


		if (doEncryption) {

	// REMOVAL OF RAND COEEFs (rNx1)
			// typename Element::Integer randVal(rand()%2);



			// generate BDI(Inxn)
			// InXn
			/*
				indexes :

				1 2
				3 4
				5 6
				7 8

				as 1 2 3 4 5 6 7 8

				values:

				1 0
				2 0
				4 0
				8 0
				0 1
				0 2
				0 4
				0 8   <- 2^(l-1)

			*/
			std::vector<Element> BDI;


			Matrix<Element> BDIMatrix = Matrix<Element>(
				[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
				N, 
				2
				);

			for (int i = 0; i < N; ++i)
			{	
				// produces 1, 2, 4 ,8, ..  (2^[l] where l = {0,1,2,3,...})
				Element power2Element(elementParams, COEFFICIENT, true);
				power2Element.SetValAtIndex(0, 1 << (i%(N/2)));
				power2Element.SwitchFormat();

				if(i < N/2){
					BDIMatrix(i, 0) = power2Element;
					BDIMatrix(i, 1) = Element(elementParams, EVALUATION, true); // zero element
				}
				else{
					BDIMatrix(i, 0) = Element(elementParams, EVALUATION, true); // zero element
					BDIMatrix(i, 1) = power2Element;
				}
			}



			// error is a distributed gaussian sampled for all Nx2 elements
			Matrix<Element> errorMatrix = Matrix<Element>(
				[elementParams, dgg]() { return make_unique<Element> (dgg, elementParams, Format::EVALUATION); },
				N, 
				2
				);


			Matrix<Element> BDITimesPlaintextMatrix = plaintext * BDIMatrix;



			Matrix<Element> randCoefficientOnesMatrix = Matrix<Element>(
				[elementParams]() { 
					Element randOnes = Element(elementParams, COEFFICIENT, true); 
					for (unsigned int j = 0; j < elementParams->GetRingDimension(); ++j) {
						randOnes.SetValAtIndex(j, rand()%2);
						randOnes.SwitchFormat();
					}	
					return make_unique<Element>(randOnes);
				},
				N, 
				1
				);

			Element pubKeyAElement(publicKey->GetPublicElements().at(1));
			
			Element pubKeyBElement(publicKey->GetPublicElements().at(0));

			Matrix<Element> publicKeyElementMatrix = Matrix<Element>(
				[elementParams]() { return make_unique<Element>(elementParams, EVALUATION, true); },
				1, 
				2
				);

			publicKeyElementMatrix(0,0) = Element(pubKeyBElement);

			publicKeyElementMatrix(0,1) = Element(pubKeyAElement);
			

			cout << randCoefficientOnesMatrix * publicKeyElementMatrix << endl << "randCoefficientOnesMatrix AFTER MULT MATRIX "  << endl;
			exit(1);

			for (int i = 0; i < N; ++i)
			{	

				Element power2Element(elementParams, COEFFICIENT, true);

				// produces 1, 2, 4 ,8, ..  (2^[l] where l = {0,1,2,3,...})
				power2Element.SetValAtIndex(0, 1 << (i%(N/2)));

				Element zeroElement(elementParams, COEFFICIENT, true);
				
				power2Element.SwitchFormat();
				zeroElement.SwitchFormat();

				if(i < N/2){

					BDI.push_back(power2Element);
					BDI.push_back(zeroElement);

					// cout << " [ " << power2Element.GetValAtIndex(0) << "   " << zeroElement.GetValAtIndex(0) << "]" << endl << endl;
					
					// // // // BDIMatrix(0, i/2) = power2Element * plaintext;
					// // // // BDIMatrix(1, i/2) = zeroElement;
				}
				else{
					
					BDI.push_back(zeroElement);
					BDI.push_back(power2Element);

					// cout << " [ " << zeroElement.GetValAtIndex(0) << "   " << power2Element.GetValAtIndex(0) << "]" << endl << endl;

					// // // // BDIMatrix(0, i/2) = zeroElement; 
					// // // // BDIMatrix(1, i/2) = power2Element * plaintext;
				}

			}


			// do u X BDI

			// // // // BDIMatrix *= plaintext;

			std::vector<Element> plaintTimesBDI;
			for (unsigned int i = 0; i < BDI.size(); ++i)
			{
				plaintTimesBDI.push_back(plaintext * BDI.at(i));

			}




			// get the public key to use as Nx2
			/*	
				1 2
				3 4
				5 6
				7 8
				is
				1 2 3 4 5 6 7 8

			*/
			std::vector<Element> pkToUse;
			for (int i = 0; i < N; ++i)
			{
				// // this is where to generate the rNx1 {0,1} and multiply into each row
				// // true for initialize to 0s
				Element randCoefficientPoly(cryptoParams->GetElementParams(), COEFFICIENT, true);

				for (unsigned int j = 0; j < cryptoParams->GetElementParams()->GetRingDimension(); ++j) {
					randCoefficientPoly.SetValAtIndex(j, rand()%2);
				}

				randCoefficientPoly.SwitchFormat();

				pkToUse.push_back(randCoefficientPoly * publicKey->GetPublicElements().at(0));
				pkToUse.push_back(randCoefficientPoly * publicKey->GetPublicElements().at(1).GetValAtIndex(i));;

			}


			// do the final addition of all parts
			std::vector<Element> ciphertextElements;
			for (int i = 0; i < N * 2; ++i)
			{

				Element errorToAdd(dgg, elementParams, Format::COEFFICIENT);

				
				// const shared_ptr<LPCryptoParametersSHIELD<Element>> newCryptoParams = cryptoParams;
				// newCryptoParams->SetDistributionParameter(0.501);

				// const typename Element::DggType &newDgg = newCryptoParams->GetDiscreteGaussianGenerator();
				// errorToAdd = Element(newDgg, elementParams, Format::COEFFICIENT);

				
				errorToAdd.SwitchFormat();
				// ciphertextElements.push_back(plaintTimesBDI.at(i) + pkToUse.at(i) + errorToAdd);
				ciphertextElements.push_back(plaintTimesBDI.at(i) + pkToUse.at(i));

			}

			ciphertext->SetElements(std::move(ciphertextElements));
			return ciphertext;


		}
		else
		{

			// Element c0(plaintext);

			// Element c1(elementParams,Format::EVALUATION,true);

			// cVector.push_back(std::move(c0));

			// cVector.push_back(std::move(c1));

			// ciphertext->SetElements(std::move(cVector));

		}

		return ciphertext;
	}

	template <class Element>
	DecryptResult LPAlgorithmSHIELD<Element>::Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		Poly *plaintext) const
	{
		const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();

		const std::vector<Element> &ciphertextElements = ciphertext->GetElements();

		const Element &privK = privateKey->GetPrivateElement();

		// Cnx2 * s2x1  (C == ciphertext lattice, s == secret key > privK) << fill in a 1 for first element in secret key


		Poly plaintextElement(privateKey->GetCryptoParameters()->GetElementParams(), COEFFICIENT, true);


		typename Element::Integer theModulus =  privateKey->GetCryptoParameters()->GetElementParams()->GetModulus();

		cout << "The modulus is : " << theModulus << endl;
		
		// # bits of security 
		int l = theModulus.GetMSB();  // bit # starts at 1

		cout << " l security bits are : " << l << endl;

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


		std::vector<Element> decryptMultiplyResults;
		for (int i = 0; i < N * 2; i+=2) // only do N/2 because we only extract first l (N=2l)
		{

			Element multRes = ciphertextElements[i] + ciphertextElements[i + 1] * privK;
			multRes.SwitchFormat();

			decryptMultiplyResults.push_back(multRes);

		}


		Poly finalPlaintext(privateKey->GetCryptoParameters()->GetElementParams(), COEFFICIENT, true);


		// for (unsigned int i = decryptMultiplyResults.size() - 1; i >= 0 ; --i)
		// {
		// 	for (int j = 0; j < l; ++j)
		// 	{


		// 		typename Element::Integer theBit = decryptMultiplyResults.at(i).GetValAtIndex(j).GetBitAtIndex(l);

		// 		cout << theBit << " ";

		// 		if(theBit > 0){
		// 			typename Element::Integer currentPolyCoefficient = finalPlaintext.GetValAtIndex(j);
		// 			finalPlaintext.SetValAtIndex(j, currentPolyCoefficient + 1 << j);
		// 		}
				
		// 		continue;

		// 	}

		// 	if(i == 0){
		// 		break;
		// 	}

		// 	cout << endl;

		// }

		for (unsigned int i = 0; i < decryptMultiplyResults.size(); ++i)
		{
			for (int j = 0; j < l; ++j)
			{

				typename Element::Integer theBit = decryptMultiplyResults.at(i).GetValAtIndex(j).GetBitAtIndex(l);

				cout << theBit << " ";

				

				if(theBit > 0){
					typename Element::Integer currentPolyCoefficient = finalPlaintext.GetValAtIndex(j);
					finalPlaintext.SetValAtIndex(j, currentPolyCoefficient + 1 << j);
				}
				

				continue;

			}

			if(i == decryptMultiplyResults.size() - 1){

				cout << endl << "POLY AT I IS : " << endl;

				for (int j = 0; j < l; ++j)
				{

					for (unsigned int k = 1; k <= privateKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2; ++k)
					{

						typename Element::Integer theBit = decryptMultiplyResults.at(i).GetValAtIndex(j).GetBitAtIndex(k);

						cout << theBit << " ";
					}

					cout << endl;

				}

				exit(1);
			
			}

			cout << endl;

		}

		// cout << finalPlaintext;
		*plaintext = finalPlaintext;
		exit(1);

		return DecryptResult(plaintext->GetLength());





		// std::vector<Element> vectorOfResultPolys;

		// cout << " THE N " << N << endl;
		// for (int i = 0; i < N; i+=2) // only do N/2 because we only extract first l (N=2l)
		// {



			/*
			Element newElement = ciphertextElements[i] + ciphertextElements[i + 1] * privK;

			// cout << " ciphertextElements at " << i <<" values length " << ciphertextElements[i].GetValues().GetLength() << endl;

			// cout << " ciphertextElements at " << i + 1 <<" values length " << ciphertextElements[i + 1].GetValues().GetLength() << endl;
			newElement.SwitchFormat();

			// extract the most significant bit
			cout << "bit at security index l : " << l << " is" << newElement.GetValues().GetValAtIndex(0).GetBitAtIndex( l ) << endl; 
			typename Element::Integer polyBit(newElement.GetValues().GetValAtIndex(0).GetBitAtIndex( l ));


			// cout << "After making the interge poly bit " <<  polyBit << endl;


			plaintextElement.SetValAtIndex((unsigned int) i, std::move(polyBit));
		

			*/

		// }


		// *plaintext = plaintextElement;
		// return DecryptResult(plaintext->GetLength());




		
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHESHIELD<Element>::EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,

	    const shared_ptr<Ciphertext<Element>> ciphertext2) const {

	    if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
	        std::string errMsg = "LPAlgorithmSHESHIELD::EvalAdd crypto parameters are not the same";
	        throw std::runtime_error(errMsg);
	    }

	    shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));
	    const std::vector<Element> &cipherText1Elements = ciphertext1->GetElements();
	    const std::vector<Element> &cipherText2Elements = ciphertext2->GetElements();
	    std::vector<Element> finalElements;

	    for (unsigned int i = 0; i < cipherText2Elements.size(); i++) {
	        finalElements.push_back(cipherText1Elements[i] + cipherText2Elements[i]);
	    }

	    newCiphertext->SetElements(finalElements);

	    return newCiphertext;

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHESHIELD<Element>::EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const {

		// shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

		// const std::vector<Element> &c1 = ciphertext1->GetElements();

		// const std::vector<Element> &c2 = ciphertext2->GetElements();

		// std::vector<Element> cNew;

		// cNew.push_back(std::move(c1[0] - c2[0]));

		// cNew.push_back(std::move(c1[1] - c2[1]));

		// newCiphertext->SetElements(std::move(cNew));

		// return newCiphertext;

		return NULL;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHESHIELD<Element>::EvalMult(
		const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const
	{

		// if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
		// 	throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
		// }

		// shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

		// const std::vector<Element> &c1 = ciphertext1->GetElements();

		// const std::vector<Element> &c2 = ciphertext2->GetElements();

		// std::vector<Element> cNew;

		// cNew.push_back(std::move(c1[0] * c2[0]));

		// cNew.push_back(std::move(c1[0] * c2[1] + c1[1] * c2[0]));

		// cNew.push_back(std::move((c1[1] * c2[1]).Negate()));

		// newCiphertext->SetElements(std::move(cNew));

		// return newCiphertext;

		return NULL;

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHESHIELD<Element>::EvalMultPlain(
		const shared_ptr<Ciphertext<Element>> ciphertext,
		const shared_ptr<Ciphertext<Element>> plaintext) const
	{

		// if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT || plaintext->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
		// 	throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
		// }

		// shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

		// const std::vector<Element> &c1 = ciphertext->GetElements();

		// const std::vector<Element> &c2 = plaintext->GetElements();

		// std::vector<Element> cNew;

		// cNew.push_back(std::move(c1[0] * c2[0]));

		// cNew.push_back(std::move(c1[1] * c2[0]));

		// newCiphertext->SetElements(std::move(cNew));

		// return newCiphertext;

		return NULL;

	}


	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHESHIELD<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const {

		shared_ptr<Ciphertext<Element>> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

		// return this->KeySwitch(ek, newCiphertext);

		return newCiphertext;

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHESHIELD<Element>::EvalNegate(const shared_ptr<Ciphertext<Element>> ciphertext) const {

		// shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

		// const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

		// Element c0 = cipherTextElements[0].Negate();
		// Element c1 = cipherTextElements[1].Negate();

		// newCiphertext->SetElements({ c0, c1 });
		// return newCiphertext;

		return NULL;
	}


	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmSHESHIELD<Element>::KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey, const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {

		// const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(originalPrivateKey->GetCryptoParameters());

		// const shared_ptr<typename Element::Params> originalKeyParams = cryptoParams->GetElementParams();

		// const BigInteger &p = cryptoParams->GetPlaintextModulus();

		// shared_ptr<LPEvalKey<Element>> keySwitchHintRelin(new LPEvalKeyRelin<Element>(originalPrivateKey->GetCryptoContext()));

		// //Getting a reference to the polynomials of new private key.
		// const Element &sNew = newPrivateKey->GetPrivateElement();

		// //Getting a reference to the polynomials of original private key.
		// const Element &s = originalPrivateKey->GetPrivateElement();

		// //Getting a refernce to discrete gaussian distribution generator.
		// const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

		// //Getting a reference to discrete uniform generator.
		// typename Element::DugType dug;

		// //Relinearization window is used to calculate the base exponent.
		// usint relinWindow = cryptoParams->GetRelinWindow();

		// //Pushes the powers of base exponent of original key polynomial onto evalKeyElements.
		// std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));

		// //evalKeyElementsGenerated hold the generated noise distribution.
		// std::vector<Element> evalKeyElementsGenerated;

		// for (usint i = 0; i < (evalKeyElements.size()); i++)
		// {
		// 	// Generate a_i vectors
		// 	Element a(dug, originalKeyParams, Format::EVALUATION);

		// 	evalKeyElementsGenerated.push_back(a); //alpha's of i

		// 										   // Generate a_i * newSK + p * e - PowerOfBase(oldSK)
		// 	Element e(dgg, originalKeyParams, Format::EVALUATION);

		// 	evalKeyElements.at(i) = (a*sNew + p*e) - evalKeyElements.at(i);

		// }

		// keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

		// keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

		// return keySwitchHintRelin;

		return NULL;
	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHESHIELD<Element>::KeySwitch(const shared_ptr<LPEvalKey<Element>> keySwitchHint, const shared_ptr<Ciphertext<Element>> cipherText) const {

		// shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(*cipherText));

		// const shared_ptr<LPCryptoParametersBV<Element>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBV<Element>>(keySwitchHint->GetCryptoParameters());

		// const shared_ptr<LPEvalKeyRelin<Element>> evalKey = std::static_pointer_cast<LPEvalKeyRelin<Element>>(keySwitchHint);

		// const std::vector<Element> &a = evalKey->GetAVector();
		// const std::vector<Element> &b = evalKey->GetBVector();

		// usint relinWindow = cryptoParamsLWE->GetRelinWindow();

		// const std::vector<Element> &c = cipherText->GetElements();

		// std::vector<Element> digitsC1;
		// Element ct1;

		// if (c.size() == 2) //case of PRE or automorphism
		// {
		// 	digitsC1 = c[1].BaseDecompose(relinWindow);
		// 	ct1 = digitsC1[0] * a[0];
		// }
		// else //case of EvalMult
		// {
		// 	digitsC1 = c[2].BaseDecompose(relinWindow);
		// 	ct1 = c[1] + digitsC1[0] * a[0];
		// }

		// Element ct0(c[0] + digitsC1[0] * b[0]);

		// //Relinearization Step.
		// for (usint i = 1; i < digitsC1.size(); ++i)
		// {
		// 	ct0 += digitsC1[i] * b[i];
		// 	ct1 += digitsC1[i] * a[i];
		// }

		// std::vector<Element> ctVector;

		// ctVector.push_back(std::move(ct0));

		// ctVector.push_back(std::move(ct1));

		// newCiphertext->SetElements(std::move(ctVector));

		// return newCiphertext;

		return NULL;

	}

	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmSHESHIELD<Element>::EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const
	{

		// shared_ptr<LPPrivateKey<Element>> originalPrivateKeySquared = std::shared_ptr<LPPrivateKey<Element>>(new LPPrivateKey<Element>(originalPrivateKey->GetCryptoContext()));

		// Element sSquare(originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement());

		// originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

		// return this->KeySwitchGen(originalPrivateKeySquared, originalPrivateKey);

		return NULL;

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmSHESHIELD<Element>::EvalAutomorphism(const shared_ptr<Ciphertext<Element>> ciphertext, usint i,
		const std::map<usint, shared_ptr<LPEvalKey<Element>>> &evalKeys) const
	{

		// shared_ptr<Ciphertext<Element>> permutedCiphertext(new Ciphertext<Element>(*ciphertext));

		// const std::vector<Element> &c = ciphertext->GetElements();

		// std::vector<Element> cNew;

		// cNew.push_back(std::move(c[0].AutomorphismTransform(i)));

		// cNew.push_back(std::move(c[1].AutomorphismTransform(i)));

		// permutedCiphertext->SetElements(std::move(cNew));

		// return this->KeySwitch(evalKeys.find(i)->second, permutedCiphertext);

		return NULL;

	}

	template <class Element>
	shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> LPAlgorithmSHESHIELD<Element>::EvalAutomorphismKeyGen(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const std::vector<usint> &indexList) const
	{

		// const Element &privateKeyElement = privateKey->GetPrivateElement();

		// usint n = privateKeyElement.GetRingDimension();

		// shared_ptr<LPPrivateKey<Element>> tempPrivateKey(new LPPrivateKey<Element>(privateKey->GetCryptoContext()));

		// shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> evalKeys(new std::map<usint, shared_ptr<LPEvalKey<Element>>>());

		// if (indexList.size() > n - 1)
		// 	throw std::runtime_error("size exceeds the ring dimension");
		// else {

		// 	for (usint i = 0; i < indexList.size(); i++)
		// 	{
		// 		Element permutedPrivateKeyElement = privateKeyElement.AutomorphismTransform(indexList[i]);

		// 		tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

		// 		(*evalKeys)[indexList[i]] = this->KeySwitchGen(tempPrivateKey, privateKey);

		// 	}

		// }

		// return evalKeys;

		return NULL;

	}

	template <class Element>
	shared_ptr<LPEvalKey<Element>> LPAlgorithmPRESHIELD<Element>::ReKeyGen(const shared_ptr<LPPrivateKey<Element>> newSK,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
	{
		// return origPrivateKey->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchGen(origPrivateKey,
			// newSK);

		return NULL;
	}

	//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
	template <class Element>
	shared_ptr<Ciphertext<Element>> LPAlgorithmPRESHIELD<Element>::ReEncrypt(const shared_ptr<LPEvalKey<Element>> EK,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
	{
		// return ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(EK, ciphertext);

		return NULL;

	}

	template <class Element>
	shared_ptr<Ciphertext<Element>> LPLeveledSHEAlgorithmSHIELD<Element>::ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const {

		// shared_ptr<Ciphertext<Element>> newcipherText(new Ciphertext<Element>(*cipherText));

		// std::vector<Element> cipherTextElements(cipherText->GetElements());

		// BigInteger plaintextModulus(cipherText->GetCryptoParameters()->GetPlaintextModulus());

		// for (auto &cipherTextElement : cipherTextElements) {
		// 	cipherTextElement.ModReduce(plaintextModulus); // this is being done at the lattice layer. The ciphertext is mod reduced.
		// }

		// newcipherText->SetElements(cipherTextElements);

		// return newcipherText;

		return NULL;
	}


	//makeSparse is not used by this scheme
	template <class Element>
	LPKeyPair<Element> LPAlgorithmMultipartySHIELD<Element>::MultipartyKeyGen(CryptoContext<Element>* cc,
		const vector<shared_ptr<LPPrivateKey<Element>>>& secretKeys,
		bool makeSparse)
	{

// 		LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));
// 		const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBV<Element>>(cc->GetCryptoParameters());
// 		const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
// 		const typename Element::Integer &p = cryptoParams->GetPlaintextModulus();
// 		const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
// 		typename Element::DugType dug;
// 		typename Element::TugType tug;

// 		//Generate the element "a" of the public key
// 		Element a(dug, elementParams, Format::EVALUATION);
// 		//Generate the secret key
// 		Element s(elementParams, Format::EVALUATION, true);

// 		//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
// 		size_t numKeys = secretKeys.size();
// 		for( size_t i = 0; i < numKeys; i++ ) {
// 			shared_ptr<LPPrivateKey<Element>> sk1 = secretKeys[i];
// 			Element s1 = sk1->GetPrivateElement();
// 			s += s1;
// 		}
// //		s.SwitchFormat();

// 		//public key is generated and set
// 		//privateKey->MakePublicKey(a, publicKey);
// 		Element e(dgg, elementParams, Format::COEFFICIENT);
// 		e.SwitchFormat();

// 		Element b = a*s + p*e;

// 		kp.secretKey->SetPrivateElement(std::move(s));
// 		kp.publicKey->SetPublicElementAtIndex(0, std::move(a));
// 		kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

// 		return kp;

		return NULL;
	}

//makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartySHIELD<Element>::MultipartyKeyGen(CryptoContext<Element>* cc,
		const shared_ptr<LPPublicKey<Element>> pk1, bool makeSparse)
	{


		// LPKeyPair<Element>	kp(new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc));
		// const shared_ptr<LPCryptoParametersBV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBV<Element>>(cc->GetCryptoParameters());
		// const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();
		// const typename Element::Integer &p = cryptoParams->GetPlaintextModulus();
		// const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
		// typename Element::DugType dug;
		// typename Element::TugType tug;

		// //Generate the element "a" of the public key
		// Element a = pk1->GetPublicElements()[1];
		// //Generate the secret key
		// Element s;

		// //Done in two steps not to use a random polynomial from a pre-computed pool
		// //Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
		// if (cryptoParams->GetMode() == RLWE) {
		// 	s = Element(dgg, elementParams, Format::COEFFICIENT);
		// }
		// else {
		// 	s = Element(tug, elementParams, Format::COEFFICIENT);
		// }
		// s.SwitchFormat();

		// //public key is generated and set
		// //privateKey->MakePublicKey(a, publicKey);
		// Element e(dgg, elementParams, Format::COEFFICIENT);
		// e.SwitchFormat();
		// //a.SwitchFormat();

		// Element b = a*s + p*e;

		// kp.secretKey->SetPrivateElement(std::move(s));
		// kp.publicKey->SetPublicElementAtIndex(0, std::move(a));
		// kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

		// return kp;

		return NULL;
	}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmMultipartySHIELD<Element>::MultipartyDecryptLead(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
{

		// const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
		// const std::vector<Element> &c = ciphertext->GetElements();
		// const Element &s = privateKey->GetPrivateElement();

		// Element b = c[0] - s*c[1];

		// shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));
		// newCiphertext->SetElements({ b });

		// return newCiphertext;

	return NULL;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmMultipartySHIELD<Element>::MultipartyDecryptMain(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
{
	// const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	// const std::vector<Element> &c = ciphertext->GetElements();

	// const Element &s = privateKey->GetPrivateElement();

	// Element b = s*c[1];

	// shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));
	// newCiphertext->SetElements({ b });

	// return newCiphertext;

	return NULL;
}


template <class Element>
DecryptResult LPAlgorithmMultipartySHIELD<Element>::MultipartyDecryptFusion(const vector<shared_ptr<Ciphertext<Element>>>& ciphertextVec,
		Poly *plaintext) const
{

	// const shared_ptr<LPCryptoParameters<Element>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
	// const BigInteger &p = cryptoParams->GetPlaintextModulus();

	// const std::vector<Element> &cElem = ciphertextVec[0]->GetElements();
	// Element b = cElem[0];

	// size_t numCipher = ciphertextVec.size();
	// for( size_t i = 1; i < numCipher; i++ ) {
	// 	const std::vector<Element> &c2 = ciphertextVec[i]->GetElements();
	// 	b -= c2[0];
	// }

	// b.SwitchFormat();	

	// // Interpolation is needed in the case of Double-CRT interpolation, for example, DCRTPoly
	// // CRTInterpolate does nothing when dealing with single-CRT ring elements, such as Poly
	// Poly interpolatedElement = b.CRTInterpolate();
	// *plaintext = interpolatedElement.SignedMod(p);

	// return DecryptResult(plaintext->GetLength());

	return DecryptResult();

}

	// Enable for LPPublicKeyEncryptionSchemeLTV
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
			throw std::logic_error("SHE feature not supported for SHIELD scheme");
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
