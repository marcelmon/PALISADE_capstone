/*
 * @file 
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
 *  This file contains google test code that exercises the big int
 *  vector library of the PALISADE lattice encryption library.
 *
 **/

//todo reduce the number of required includes
#include "include/gtest/gtest.h"
#include <iostream>
#include <fstream>

#include "../lib/lattice/dcrtpoly.h"
#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "utils/utilities.h"
#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

/*
  int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  }
*/

class UnitTestubintvec : public ::testing::Test {
protected:
  virtual void SetUp() {
    // Code here will be called before each test
    // (right before the constructor).

  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/* list of tests left to run

   //METHODS
   //todo write Div and /= vector scalar and vector vector
   
   Exp(const bint_el_t &b)

   GetDigitAtIndexForBase(usint index, usint base) const;
   
   //JSON FACILITY
   Serialize()
   Deserialize()
*/

/************************************************/
/*	TESTING BASIC METHODS OF exp_int::xubintvec CLASS        */
/************************************************/
TEST(UTubintvec,ctor_access_eq_neq){

  exp_int::xubintvec m(5); // calling constructor to create a vector of length 5
                 //note all values are zero.
  exp_int::xubintvec n(5);

  usint i;
  usint j;

  EXPECT_EQ(5U,m.size())<< "Failure in size()";
  EXPECT_EQ(5U,n.size())<< "Failure in size()";

  // Old fashioned soon to be deprecated way of 
  // setting value of the value at different index locations

  //test SetValAtIndex(string)
  m.SetValAtIndex(0,"9868");  
  m.SetValAtIndex(1,"5879");
  m.SetValAtIndex(2,"4554");
  m.SetValAtIndex(3,"2343");
  m.SetValAtIndex(4,"4624");

  //old fashioned way of expect
  EXPECT_EQ(9868U,m.GetValAtIndex(0).ConvertToUsint())
    << "Failure in SetValAtIndex(str)";
  EXPECT_EQ(5879U,m.GetValAtIndex(1).ConvertToUsint())
<< "Failure in SetValAtIndex(str)";
  EXPECT_EQ(4554U,m.GetValAtIndex(2).ConvertToUsint())
<< "Failure in SetValAtIndex(str)";
  EXPECT_EQ(2343U,m.GetValAtIndex(3).ConvertToUsint())
<< "Failure in SetValAtIndex(str)";
  EXPECT_EQ(4624U,m.GetValAtIndex(4).ConvertToUsint())
<< "Failure in SetValAtIndex(str)";

  EXPECT_EQ(exp_int::xubint(9868U),m.GetValAtIndex(0))<< "Failure in SetValAtIndex()";
  EXPECT_EQ(exp_int::xubint(5879U),m.GetValAtIndex(1))<< "Failure in SetValAtIndex()";
  EXPECT_EQ(exp_int::xubint(4554U),m.GetValAtIndex(2))<< "Failure in SetValAtIndex()";
  EXPECT_EQ(exp_int::xubint(2343U),m.GetValAtIndex(3))<< "Failure in SetValAtIndex()";
  EXPECT_EQ(exp_int::xubint(4624U),m.GetValAtIndex(4))<< "Failure in SetValAtIndex()";

  //new way of setting value of the value at different index locations
  n[0]="4";
  n[1]=9;   //int (implied)
  n[2]=exp_int::xubint("66"); //exp_int::xubint
  n[3] = 33L;  //long
  n[4] = 7UL;  //unsigned long

  // new way of accessing
  EXPECT_EQ(exp_int::xubint(4),n[0])<< "Failure in []";
  EXPECT_EQ(exp_int::xubint(9),n[1])<< "Failure in []";
  EXPECT_EQ(exp_int::xubint(66),n[2])<< "Failure in []";
  EXPECT_EQ(exp_int::xubint(33),n[3])<< "Failure in []";
  EXPECT_EQ(exp_int::xubint(7),n[4])<< "Failure in []";

  //test SetValAtIndex(exp_int::xubint)
  n.SetValAtIndex(0,exp_int::xubint("4"));
  n.SetValAtIndex(1,exp_int::xubint("9"));
  n.SetValAtIndex(2,exp_int::xubint("66"));
  n.SetValAtIndex(3,exp_int::xubint("33"));
  n.SetValAtIndex(4,exp_int::xubint("7"));


  EXPECT_EQ(exp_int::xubint(4),n[0])<< "Failure in SetValAtIndex(exp_int::xubint)";
  EXPECT_EQ(exp_int::xubint(9),n[1])<< "Failure in SetValAtIndex(exp_int::xubint)";
  EXPECT_EQ(exp_int::xubint(66),n[2])<< "Failure in SetValAtIndex(exp_int::xubint)";
  EXPECT_EQ(exp_int::xubint(33),n[3])<< "Failure in SetValAtIndex(exp_int::xubint)";
  EXPECT_EQ(exp_int::xubint(7),n[4])<< "Failure in SetValAtIndex(exp_int::xubint)";



  m+=n;

  usint expectedResult[5] = {9872,5888,4620,2376,4631};

  for (i=0,j=0;j<5;i++,j++) {
    EXPECT_EQ (expectedResult[i], (m.GetValAtIndex(j)).ConvertToUsint())
      << "Failure testing method_plus_equals";
  }

  //test initializer list of various types
  exp_int::xubintvec expectedvecstr(5);
  expectedvecstr = {"9872","5888","4620","2376","4631"}; //strings
  EXPECT_EQ (expectedvecstr, m)<< "Failure string initializer list";
  
  exp_int::xubintvec expectedvecint(5);
  expectedvecint = {exp_int::xubint(9872U),exp_int::xubint(5888U),exp_int::xubint(4620U),exp_int::xubint(2376U),exp_int::xubint(4631U)}; //ubints
  EXPECT_EQ (expectedvecint, m)<< "Failure exp_int::xubint initializer list";

  expectedvecint = {9872U,5888u,4620u,2376u,4631u}; //usints
  EXPECT_EQ (expectedvecint, m)<< "Failure usint initializer list";

  expectedvecint = {9872,5888,4620,2376,4631}; //ints (compiler promotes)
  EXPECT_EQ (expectedvecint, m)<< "Failure int initializer list";

  //test Single()
  exp_int::xubintvec s = exp_int::xubintvec::Single(exp_int::xubint("3"));
		      
  EXPECT_EQ(1U, s.size()) <<"Failure Single.size()";
  EXPECT_EQ(exp_int::xubint(3), s[0]) <<"Failure Single() value";

  // test assignment of single exp_int::xubint (puts it in the 0 the position), zeros
  // out the rest
  //test that the vector is zeroed on init like this.
  exp_int::xubintvec eqtest(10);
  EXPECT_EQ ( 10U, eqtest.size()) << "Failure create exp_int::xubintvec of 10 zeros";

  for (i = 0; i< eqtest.size(); i++) {
    EXPECT_EQ ( exp_int::xubint(0), eqtest[i]) << "Failure create exp_int::xubintvec of zeros";
  }

  // test assignment of single exp_int::xubint
  eqtest = exp_int::xubint(1);
  EXPECT_EQ (exp_int::xubint(1),  eqtest[0]) << "Failure assign single exp_int::xubint 0 index";
  for (i = 1; i< eqtest.size(); i++) {
    EXPECT_EQ ( exp_int::xubint(0), eqtest[i]) << "Failure assign single exp_int::xubint nonzero index";
  }

  // test assignment of single usint
  eqtest = 5U;
  EXPECT_EQ (exp_int::xubint(5U),  eqtest[0]) << "Failure assign single exp_int::xubint 0 index";
  for (i = 1; i< eqtest.size(); i++) {
    EXPECT_EQ ( exp_int::xubint(0U), eqtest[i]) << "Failure assign single exp_int::xubint nonzero index";
  }


  //test comparisons == and !=
  m = n;
  bool test1 = m==n;
  bool test2 = m!=n;
  EXPECT_TRUE(test1)<<"Failure ==";
  EXPECT_FALSE(test2)<<"Failure !=";

  m = n+n;
  test1 = m==n;
  test2 = m!=n;
  EXPECT_FALSE(test1)<<"Failure ==";
  EXPECT_TRUE(test2)<<"Failure !=";

  for (size_t i = 0; i < m.size(); i++) {
    m[i] = n[i]; //test both lhs and rhs []
  }
  test1 = m==n;
  EXPECT_TRUE(test1)<<"Failure [] lhs rhs";

}

TEST(UTubintvec,mod){

  exp_int::xubintvec m(10); // calling constructor to create a vector of length 10 zeroed

  usint i;
  usint j;
	
  //setting value of the value at different index locations
  m.SetValAtIndex(0,"987968");
  m.SetValAtIndex(1,"587679");
  m.SetValAtIndex(2,"456454");
  m.SetValAtIndex(3,"234343");
  m.SetValAtIndex(4,"769789");
  m.SetValAtIndex(5,"465654");
  m.SetValAtIndex(6,"79");
  m.SetValAtIndex(7,"346346");
  m.SetValAtIndex(8,"325328");
  m.SetValAtIndex(9,"7698798");	

  exp_int::xubint q("233");		//calling costructor of exp_int::xubint Class to create object for modulus
  exp_int::xubintvec calculatedResult = m.Mod(q);
  usint expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};	// the expected values are stored as one dimensional integer array

  for (i=0,j=0;i<10;i++,j++)
    {
      EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(j)).ConvertToUsint());
    }
}

TEST(UTubintvec,basic_vector_scalar_math_1_limb){
  //basic vector math with 1 limb entries
  // a1:
  std::vector<std::string>  a1sv =
    { "127753", "077706",
      "017133", "022582",
      "112132", "027625",
      "126773", "008924",
      "125972", "002551",
      "113837", "112045",
      "100953", "077352",
      "132013", "057029", };
  
  exp_int::xubintvec a1(a1sv);
  exp_int::xubintvec a1op1(a1.size());
  exp_int::xubintvec a1op1test(a1.size());
  
  exp_int::xubint myone(1);

  // test all scalar operations with ONE as the operator term

  // add
  for (usint i = 0; i < a1.size();i ++){ //build test vector
    a1op1[i] = a1[i]+myone;
  }

  a1op1test = a1.Add(myone);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Add()"; 

  a1op1test = a1 + myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar +";   

  a1op1test = a1;
  a1op1test += myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar +=";   

  // sub
  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]-myone;
  }
  a1op1test = a1.Sub(myone);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Sub()"; 

  a1op1test = a1 - myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar -";   

  a1op1test = a1;
  a1op1test -= myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar -=";   

  // multiply
  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]*myone;
  }
  a1op1test = a1.Mul(myone);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Mul()"; 

  a1op1test = a1 * myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar *";   

  a1op1test = a1;
  a1op1test *= myone;
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar *=";   

}



TEST(UTubintvec,basic_vector_vector_math_1_limb){
  //basic vector math with 1 limb entries
  // a1:
  exp_int::xubintvec a1;
  a1= {   "127753", "077706",
	  "017133", "022582",
	  "112132", "027625",
	  "126773", "008924",
	  "125972", "002551",
	  "113837", "112045",
	  "100953", "077352",
	  "132013", "057029",};

  // b1:
  exp_int::xubintvec b1;
  b1 = {"066773", "069572",
	"142134", "141115",
	"123182", "155822",
	"128147", "094818",
	"135782", "030844",
	"088634", "099407",
	"053647", "111689",
	"028502", "026401", };



  // add1:
  exp_int::xubintvec add1;
  add1 = {"194526", "147278",
	  "159267", "163697",
	  "235314", "183447",
	  "254920", "103742",
	  "261754", "033395",
	  "202471", "211452",
	  "154600", "189041",
	  "160515", "083430", };

  // sub1:
#if 0//set to 1 if we allow b>a in subtraction
  std::vector<std::string>  sub1sv = 
    {"060980", "008134",
     "18446744073709426615", "18446744073709433083",
     "18446744073709540566", "18446744073709423419",
     "18446744073709550242", "18446744073709465722",
     "18446744073709541806", "18446744073709523323",
     "025203", "012638",
     "047306", "18446744073709517279",
     "103511", "030628", };

#else
  std::vector<std::string> sub1sv = 

    {"060980", "008134",
     "000000", "000000",
     "000000", "000000",
     "000000", "000000",
     "000000", "000000",
     "025203", "012638",
     "047306", "000000",
     "103511", "030628", };
#endif
  exp_int::xubintvec sub1(sub1sv);

  // mul1:
  exp_int::xubintvec mul1;
  mul1 = 
    {"08530451069",
     "05406161832",
     "02435181822",
     "03186658930",
     "13812644024",
     "04304582750",
     "16245579631",
     "00846155832",
     "17104730104",
     "00078683044",
     "10089828658",
     "11138057315",
     "05415825591",
     "08639367528",
     "03762634526",
     "01505622629", };

  exp_int::xubintvec c1;
  exp_int::xubintvec d1;

  // test math for case 1
  c1 = a1.Add(b1);
  EXPECT_EQ (c1, add1) << "Failure 1 limb vector vector Add()";

  c1 = a1 + b1;
  EXPECT_EQ (c1, add1) << "Failure 1 limb vector vector +";

  d1 = a1;
  d1+=b1;
  EXPECT_EQ (d1, add1) << "Failure 1 limb vector vector +=";

  c1 = a1.Sub(b1);
  EXPECT_EQ (c1, sub1) << "Failure 1 limb vector vector Sub()";

  c1 = a1 - b1;
  EXPECT_EQ (c1, sub1) << "Failure 1 limb vector vector -";

  d1 = a1;
  d1 -= b1;
  EXPECT_EQ (d1, sub1) << "Failure 1 limb vector vector -=";


  c1 = a1.Mul(b1);
  EXPECT_EQ (c1, mul1) << "Failure 1 limb vector vector Mul()";

  c1 = a1 * b1;
  EXPECT_EQ (c1, mul1) << "Failure 1 limb vector vector *";

  d1 = a1;
  d1 *= b1;
  EXPECT_EQ (d1, mul1) << "Failure 1 limb vector vector *=";

}


TEST(UTubintvec,basic_vector_scalar_mod_math_1_limb){
  //basic vector scalar mod math
  //todo this is very simple, should probably add sub mul by bigger numbers.

  // q1 modulus 1:
  exp_int::xubint q1("163841");

  //note here is another way to define a exp_int::xubintvec
  // a1:
  std::vector<std::string>  a1sv =
    { "127753", "077706",
      "017133", "022582",
      "112132", "027625",
      "126773", "008924",
      "125972", "002551",
      "113837", "112045",
      "100953", "077352",
      "132013", "057029", };
  
  exp_int::xubintvec a1(a1sv);
  exp_int::xubintvec a1op1(a1.size());
  exp_int::xubintvec a1op1test(a1.size());
  
  exp_int::xubint myone(1);
  
  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]+myone;
    a1op1[i] %= q1;
  }
  a1op1test = a1.ModAdd(myone, q1);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Add()"; 

  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]-myone;
    a1op1[i] %= q1;
  }
  a1op1test = a1.ModSub(myone, q1);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Sub()"; 

  for (usint i = 0; i < a1.size();i ++){
    a1op1[i] = a1[i]*myone;
    a1op1[i] %= q1;
  }
  a1op1test = a1.ModMul(myone, q1);
  EXPECT_EQ(a1op1, a1op1test)<< "Failure vector scalar Mul()"; 

}


TEST(UTubintvec,basic_vector_vector_mod_math_1_limb){

  // q1 modulus 1:
  exp_int::xubint q1("163841");

  // a1:
  exp_int::xubintvec a1;
  a1 = { "127753", "077706",
	 "017133", "022582",
	 "112132", "027625",
	 "126773", "008924",
	 "125972", "002551",
	 "113837", "112045",
	 "100953", "077352",
	 "132013", "057029", };

  // b1:
  exp_int::xubintvec b1;
  b1 = {"066773", "069572",
	"142134", "141115",
	"123182", "155822",
	"128147", "094818",
	"135782", "030844",
	"088634", "099407",
	"053647", "111689",
	"028502", "026401", };
 
  // modadd1:
  exp_int::xubintvec modadd1;
  modadd1 = {"030685", "147278",
	     "159267", "163697",
	     "071473", "019606",
	     "091079", "103742",
	     "097913", "033395",
	     "038630", "047611",
	     "154600", "025200",
	     "160515", "083430", };

  // modsub1:
  std::vector<std::string>  modsub1sv = 
    {"060980", "008134",
     "038840", "045308",
     "152791", "035644",
     "162467", "077947",
     "154031", "135548",
     "025203", "012638",
     "047306", "129504",
     "103511", "030628", };
  exp_int::xubintvec modsub1(modsub1sv);

  // modmul1:
  std::vector<std::string>  modmul1sv = 
    {"069404", "064196",
     "013039", "115321",
     "028519", "151998",
     "089117", "080908",
     "057386", "039364",
     "008355", "146135",
     "061336", "031598",
     "025961", "087680", };
  exp_int::xubintvec modmul1(modmul1sv);

  exp_int::xubintvec c1;
 //now Mod operations
  c1 = a1.ModAdd(b1,q1);
  EXPECT_EQ (c1, modadd1) << "Failure 1 limb vector vector ModAdd()";    

  c1 = a1.ModSub(b1,q1);
  EXPECT_EQ (c1, modsub1) << "Failure 1 limb vector vector ModSub()";   

  c1 = a1.ModMul(b1,q1);
  EXPECT_EQ (c1, modmul1) << "Failure 1 limb vector vector ModMul()";   

  c1 = a1.Add(b1);
  c1  %= q1;
  EXPECT_EQ (c1, modadd1) << "Failure 1 limb vector scalar %";   

}


TEST(UTubintvec,basic_vector_scalar_math_2_limb){
  //basic vector math with 2 limb entries
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };

  
  exp_int::xubintvec a2(a2sv);
  exp_int::xubintvec a2op1(a2.size());
  exp_int::xubintvec a2op1test(a2.size());
  
  exp_int::xubint myone(1);
  
  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]+myone;
  }
  a2op1test = a2.Add(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Add()"; 

  a2op1test = a2 + myone;
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar +";   

  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]-myone;
  }
  a2op1test = a2.Sub(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Sub()"; 

  a2op1test = a2 - myone;
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar -";   

  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]*myone;
  }
  a2op1test = a2.Mul(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Mul()"; 

  a2op1test = a2 * myone;
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar *";   

}

TEST(UTubintvec,basic_vector_vector_math_2_limb){

  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  exp_int::xubintvec a2(a2sv);

  // b2:
  std::vector<std::string>  b2sv = 
    {"0698898215124963", "0039832572186149",
     "1835473200214782", "1041547470449968",
     "1076152419903743", "0433588874877196",
     "2336100673132075", "2990190360138614",
     "0754647536064726", "0702097990733190",
     "2102063768035483", "0119786389165930",
     "3976652902630043", "3238750424196678",
     "2978742255253796", "2124827461185795", };

  exp_int::xubintvec b2(b2sv);

  // add2:
  std::vector<std::string>  add2sv = 
    {"0884123387923218", "0138712237895312",
     "5332883231566040", "5053979403959223",
     "2619173177932324", "0568683443309337",
     "6313055010273814", "7020538881695734",
     "0930588339595881", "1137334268426157",
     "5406716417105627", "2152306408779744",
     "4352402055428422", "7171953935869933",
     "5272176371413734", "3326240528363988", };
  exp_int::xubintvec add2(add2sv);
  // sub2:
#if 0 //set to 1 if we allow b>a in subtraction
  std::vector<std::string>  sub2sv = 
    {"18446230400667224908", "0059047093523014",
     "1661936831136476", "2970884463059287",
     "0466868338124838", "18446445579403106561",
     "1640853664009664", "1040158161418506",
     "18446165366977018045", "18446477211996511393",
     "1202588881034661", "1912733630447884",
     "18443143169959719952", "0694453087476577",
     "18446058765570457758", "18445820659315544014", };

#else
  std::vector<std::string>  sub2sv = 
    {"0000000000000000", "0059047093523014",
     "1661936831136476", "2970884463059287",
     "0466868338124838", "0000000000000000",
     "1640853664009664", "1040158161418506",
     "0000000000000000", "0000000000000000",
     "1202588881034661", "1912733630447884",
     "0000000000000000", "0694453087476577",
     "0000000000000000", "0000000000000000", };

#endif
  exp_int::xubintvec sub2(sub2sv);

  // mul2:
  std::vector<std::string>  mul2sv = 
    {"00129453542664913267883213339565",
     "00003938631422102517149330983287",
     "06419402382707574566639285895756",
     "04179138330699238739092142453840",
     "01660525522714165323210462878683",
     "00058575501928512376649634356636",
     "09290565704012341618368342178425",
     "12051509297159015143330318631680",
     "00132773293878034164433437538530",
     "00305578516062424854278036474730",
     "06946590599552827582889547919552",
     "00243468234057004000432166157020",
     "01494223959136453394722407100297",
     "12738664541883618180978992446890",
     "06831549111446250063725117624648",
     "02552795477367678807574345368435", };
  exp_int::xubintvec mul2(mul2sv);


  exp_int::xubintvec c2;
  exp_int::xubintvec d2;

  // test math for case 

  c2 = a2.Add(b2);
  EXPECT_EQ (c2, add2) << "Failure 2 limb vector vector Add()";
  c2 = a2 + b2;
  EXPECT_EQ (c2, add2) << "Failure 2 limb vector vector +";
  d2 = a2;
  d2+=b2;
  EXPECT_EQ (d2, add2) << "Failure 2 limb vector vector +=";


  c2 = a2.Sub(b2);
  EXPECT_EQ (c2, sub2) << "Failure 2 limb vector vector Sub()";
  c2 = a2 - b2;
  EXPECT_EQ (c2, sub2) << "Failure 2 limb vector vector -";
  d2 = a2;
  d2 -= b2;
  EXPECT_EQ (d2, sub2) << "Failure 2 limb vector vector -=";

  c2 = a2.Mul(b2);
  EXPECT_EQ (c2, mul2) << "Failure 2 limb vector vector Mul()";
  c2 = a2 * b2;
  EXPECT_EQ (c2, mul2) << "Failure 2 limb vector vector *";
  d2 = a2;
  d2 *= b2;
  EXPECT_EQ (d2, mul2) << "Failure 2 limb vector vector *=";

}


TEST(UTubintvec,basic_vector_scalar_mod_math_2_limb){
  //basic vector scalar mod math
  //todo this is very simple, should probably add sub mul by bigger numbers.

  // q2:
  exp_int::xubint q2("4057816419532801");
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  
  exp_int::xubintvec a2(a2sv);
  exp_int::xubintvec a2op1(a2.size());
  exp_int::xubintvec a2op1test(a2.size());
  
  exp_int::xubint myone(1);
  
  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]+myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModAdd(myone, q2);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Add()"; 

  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]-myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModSub(myone, q2);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Sub()"; 

  for (usint i = 0; i < a2.size();i ++){
    a2op1[i] = a2[i]*myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModMul(myone, q2);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar Mul()"; 

}


TEST(UTubintvec,basic_vector_vector_mod_math_2_limb){

  // q2:
  exp_int::xubint q2("4057816419532801");
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  exp_int::xubintvec a2(a2sv);

  // b2:
  std::vector<std::string>  b2sv = 
    {"0698898215124963", "0039832572186149",
     "1835473200214782", "1041547470449968",
     "1076152419903743", "0433588874877196",
     "2336100673132075", "2990190360138614",
     "0754647536064726", "0702097990733190",
     "2102063768035483", "0119786389165930",
     "3976652902630043", "3238750424196678",
     "2978742255253796", "2124827461185795", };

  exp_int::xubintvec b2(b2sv);

  // modadd2:
  std::vector<std::string>  modadd2sv = 
    {"0884123387923218", "0138712237895312",
     "1275066812033239", "0996162984426422",
     "2619173177932324", "0568683443309337",
     "2255238590741013", "2962722462162933",
     "0930588339595881", "1137334268426157",
     "1348899997572826", "2152306408779744",
     "0294585635895621", "3114137516337132",
     "1214359951880933", "3326240528363988", };
  exp_int::xubintvec modadd2(modadd2sv);

  // modsub2:
  std::vector<std::string>  modsub2sv = 
    {"3544143377206093", "0059047093523014",
     "1661936831136476", "2970884463059287",
     "0466868338124838", "3759322113087746",
     "1640853664009664", "1040158161418506",
     "3479109686999230", "3790954706492578",
     "1202588881034661", "1912733630447884",
     "0456912669701137", "0694453087476577",
     "3372508280438943", "3134402025525199", };
  exp_int::xubintvec modsub2(modsub2sv);

  // modmul2:
  std::vector<std::string>  modmul2sv = 
    {"0585473140075497", "3637571624495703",
     "1216097920193708", "1363577444007558",
     "0694070384788800", "2378590980295187",
     "0903406520872185", "0559510929662332",
     "0322863634303789", "1685429502680940",
     "1715852907773825", "2521152917532260",
     "0781959737898673", "2334258943108700",
     "2573793300043944", "1273980645866111", };
  exp_int::xubintvec modmul2(modmul2sv);

  exp_int::xubintvec c2;

  //now Mod operations
  c2 = a2.ModAdd(b2,q2);
  EXPECT_EQ (c2, modadd2) << "Failure 2 limb vector vector ModAdd()";    
  
  c2 = a2.ModSub(b2,q2);
  EXPECT_EQ (c2, modsub2) << "Failure 2 limb vector vector ModSub()";   
  
  c2 = a2.ModMul(b2,q2);
  EXPECT_EQ (c2, modmul2) << "Failure 2 limb vector vector ModMul()";   

  c2 = a2.Add(b2);
  c2 %= q2;
  EXPECT_EQ (c2, modadd2) << "Failure 2 limb vector scalar %";   

  
}

TEST(UTubintvec,basic_vector_vector_math_big_numbers){

  // test some very big numbers
  exp_int::xubintvec a3;
  a3 = { 
    "2259002487796164904665772121894078584543401744155154298312726209247751689172189255653866355964200768484575418973864307364757237946940733747446643725054",
    "1478743816308009734668992873633380110912159803397999015955212019971253231528589466789603074746010444199132421555598329082557053986240265071537647362089",
    "2442250766561334341166822783674395133995556495312318016431141348749482739749788174173081312927274880146329980363424977565638001056841245678661782610982",
    "917779106114096279364098211126816308037915672568153320523308800097705587686270523428976942621563981845568821206569141624247183330715577260930218556767",
    "214744931049447103852875386182628152420432967632133352449560778740158135437968557572597545037670326240142368149137864407874100658923913041236510842284",
    "3022931024526554241483841300690432083112912011870712018209552253068347592628043101662926263810401378532416655773738499681026278335470355055192240903881",
    "2177879458107855257699914331737144896274676269055062432826552808869348125407671199582563543692287114712642299482144959316835614426673048987634699368975",
    "297233451802123294436846683552230198845414118375785255038220841170372509047202030175469239142902723134737621108313142071558385068315554041062888072990"};

  exp_int::xubintvec b3;
  b3 = {
    "1746404952192586268381151521422372143182145525977836700420382237240400642889251297954418325675184427789348433626369450669892557208439401215109489355089",
    "220598825371098531288665964851212313477741334812037568788443848101743931352326362481681721872150902208420539619641973896119680592696228972313317042316",
    "1636408035867347783699588740469182350452165486745277203525427807971352063169622066488977229506420856017031482691439089288020262006748233954177669740311",
    "1391860681743495586446518646883933051685658718352722633694285758474124803847473349064660555618847951719510263829699292297119131926436045214364252430665",
    "840450278810654165061961485691366961514650606247291814263792869596294713810125269780258316551932763106025157596216051681623225968811609560121609943365",
    "2329731862150094912355786583702878434766436140738594274867891494713002534085652731920888891507522355867974791619686673574928137376468103839586921126803",
    "3059472316627396548271906051517665887700234192652488639437431254697285170484189458770168152800520702020313091234437806236204196526193455750117363744648",
    "132216870748476988853044482759545262615616157934129470128771906579101230690441206392939162889560305016204867157725209170345968349185675785497832527174"};

  exp_int::xubintvec add3;
  add3 = {
    "4005407439988751173046923643316450727725547270132990998733108446488152332061440553608284681639385196273923852600233758034649795155380134962556133080143",
    "1699342641679108265957658838484592424389901138210036584743655868072997162880915829271284796618161346407552961175240302978676734578936494043850964404405",
    "4078658802428682124866411524143577484447721982057595219956569156720834802919410240662058542433695736163361463054864066853658263063589479632839452351293",
    "2309639787857591865810616858010749359723574390920875954217594558571830391533743872493637498240411933565079085036268433921366315257151622475294470987432",
    "1055195209860101268914836871873995113935083573879425166713353648336452849248093827352855861589603089346167525745353916089497326627735522601358120785649",
    "5352662886676649153839627884393310517879348152609306293077443747781350126713695833583815155317923734400391447393425173255954415711938458894779162030684",
    "5237351774735251805971820383254810783974910461707551072263984063566633295891860658352731696492807816732955390716582765553039810952866504737752063113623",
    "429450322550600283289891166311775461461030276309914725166992747749473739737643236568408402032463028150942488266038351241904353417501229826560720600164",
  };

  exp_int::xubintvec sub3;
#if 0 // if a <b != 0
  sub3 = {

    "512597535603578636284620600471706441361256218177317597892343972007351046282937957699448030289016340695226985347494856694864680738501332532337154369965",
    "1258144990936911203380326908782167797434418468585961447166768171869509300176263104307921352873859541990711881935956355186437373393544036099224330319773",
    "805842730693986557467234043205212783543391008567040812905713540778130676580166107684104083420854024129298497671985888277617739050093011724484112870671",
    "-474081575629399307082420435757116743647743045784569313170976958376419216161202825635683612997283969873941442623130150672871948595720467953434033873898",
    "-625705347761207061209086099508738809094217638615158461814232090856136578372156712207660771514262436865882789447078187273749125309887696518885099101081",
    "693199162376459329128054716987553648346475871132117743341660758355345058542390369742037372302879022664441864154051826106098140959002251215605319777078",
    "-881592858519541290571991719780520991425557923597426206610878445827937045076518259187604609108233587307670791752292846919368582099520406762482664375673",
    "165016581053646305583802200792684936229797960441655784909448934591271278356760823782530076253342418118532753950587932901212416719129878255565055545816",
  };
#else
  sub3 = {
    "512597535603578636284620600471706441361256218177317597892343972007351046282937957699448030289016340695226985347494856694864680738501332532337154369965",
    "1258144990936911203380326908782167797434418468585961447166768171869509300176263104307921352873859541990711881935956355186437373393544036099224330319773",
    "805842730693986557467234043205212783543391008567040812905713540778130676580166107684104083420854024129298497671985888277617739050093011724484112870671",
    "0",
    "0",
    "693199162376459329128054716987553648346475871132117743341660758355345058542390369742037372302879022664441864154051826106098140959002251215605319777078",
    "0",
    "165016581053646305583802200792684936229797960441655784909448934591271278356760823782530076253342418118532753950587932901212416719129878255565055545816",
  };

#endif

  exp_int::xubintvec mul3;
  mul3 = {
    "3945133131702594815505313517401955213422212906003207160550224827247798380158544728883063176021386698520393904638342934533842147122672165690895381911371610821805521968761803943619144153796694548166886289821562857014841953651542530764805091829231222294952980980415012824805935628205244762503711091699806",
    "326209148902322443940640858428575655800462302664603787971446127213213943734156672029644165209545417568093927431571229737889388146825783637352297738793838379605489067990018974600686396516030634863264832676726271905502450934842280843356017145798689170307553117850929852381350172055754068242724987158124",
    "3996518780004157625822415090647195375113582969537197325148397412987198668923299617655210998096768023432082550758182396647942738526222744503727730011083759641549078217904703406652423388993758005327181681934139933811259379898260107828051593334782557076645183323051795081283059651277095553321507476695402",
    "1277420652325902025823941663776494108926907091298812026686913886255674556691423716926727654799242553261895325995328828781861742245816072709575972687084748197171401854637034395082914459549271628438335228941663439445078782967098628431321726541159959431168664395766811100936463603966672711390068034060055",
    "180482437173682522960622020074582069971312997254639094063163947161104892043282487992242731589845620793992570111151202501208695820304854653522742492363941014162204782359669275314022851900215535563463499305020501669842254296096007609248733286624445014836059554190198244087213898342303628140365687245660",
    "7042618724921543448640048538894511085292095571328770917692070389597411133134433816609162364316153062666473265645864944271040483942778852526551730898067321099186001336307471882872329470753794993395722072009141582152086557176991299394829487910282094077082362155957220820918292438371443386247463735822443",
    "6663161911032458957637091338021552428846954075003065194738662366725753407230661950428910863564465232331799241680463789414149597794741173506193627020975596905904768316492860476695706055515048793725930388147468496386353338682120062327205347835675397402217405736179640771952939314867939122494628633495800",
    "39299276879045000335778052745261012743983854821402827577095882287055142208918031875556030922752660239994854929566549812623040336147884733019208891176315622960662348446192621970759838878368953344844095066240968924128522243769943119204473694089774742680964827784964421418174674383861285589714670430260",
  };


  exp_int::xubintvec c3;
  exp_int::xubintvec d3;

  // test math for case 

  c3 = a3.Add(b3);
  EXPECT_EQ (c3, add3) << "Failure big number vector vector Add()";
  c3 = a3 + b3;
  EXPECT_EQ (c3, add3) << "Failure big number vector vector +";
  d3 = a3;
  d3+=b3;
  EXPECT_EQ (d3, add3) << "Failure big number vector vector +=";


  c3 = a3.Sub(b3);
  EXPECT_EQ (c3, sub3) << "Failure big number vector vector Sub()";
  c3 = a3 - b3;
  EXPECT_EQ (c3, sub3) << "Failure big number vector vector -";
  d3 = a3;
  d3 -= b3;
  EXPECT_EQ (d3, sub3) << "Failure big number vector vector -=";

  c3 = a3.Mul(b3);
  EXPECT_EQ (c3, mul3) << "Failure big number vector vector Mul()";
  // c3 = a3 * b3;
  // EXPECT_EQ (c3, mul3) << "Failure big number vector vector *";
  // d3 = a3;
  // d3 *= b3;
  // EXPECT_EQ (d3, mul3) << "Failure big number vector vector *=";

}




TEST(UTubintvec,basic_vector_vector_mod_math_big_numbers){

  // q3:
  exp_int::xubint q3("3273390607896141870013189696827599152216642046043064789483291368096133796404674554883270092325904157150886684127560071009217256545885393053328527589431");
  exp_int::xubintvec a3;
  a3 = { 
    "2259002487796164904665772121894078584543401744155154298312726209247751689172189255653866355964200768484575418973864307364757237946940733747446643725054",
    "1478743816308009734668992873633380110912159803397999015955212019971253231528589466789603074746010444199132421555598329082557053986240265071537647362089",
    "2442250766561334341166822783674395133995556495312318016431141348749482739749788174173081312927274880146329980363424977565638001056841245678661782610982",
    "917779106114096279364098211126816308037915672568153320523308800097705587686270523428976942621563981845568821206569141624247183330715577260930218556767",
    "214744931049447103852875386182628152420432967632133352449560778740158135437968557572597545037670326240142368149137864407874100658923913041236510842284",
    "3022931024526554241483841300690432083112912011870712018209552253068347592628043101662926263810401378532416655773738499681026278335470355055192240903881",
    "2177879458107855257699914331737144896274676269055062432826552808869348125407671199582563543692287114712642299482144959316835614426673048987634699368975",
    "297233451802123294436846683552230198845414118375785255038220841170372509047202030175469239142902723134737621108313142071558385068315554041062888072990"};

  exp_int::xubintvec b3;
  b3 = {
    "1746404952192586268381151521422372143182145525977836700420382237240400642889251297954418325675184427789348433626369450669892557208439401215109489355089",
    "220598825371098531288665964851212313477741334812037568788443848101743931352326362481681721872150902208420539619641973896119680592696228972313317042316",
    "1636408035867347783699588740469182350452165486745277203525427807971352063169622066488977229506420856017031482691439089288020262006748233954177669740311",
    "1391860681743495586446518646883933051685658718352722633694285758474124803847473349064660555618847951719510263829699292297119131926436045214364252430665",
    "840450278810654165061961485691366961514650606247291814263792869596294713810125269780258316551932763106025157596216051681623225968811609560121609943365",
    "2329731862150094912355786583702878434766436140738594274867891494713002534085652731920888891507522355867974791619686673574928137376468103839586921126803",
    "3059472316627396548271906051517665887700234192652488639437431254697285170484189458770168152800520702020313091234437806236204196526193455750117363744648",
    "132216870748476988853044482759545262615616157934129470128771906579101230690441206392939162889560305016204867157725209170345968349185675785497832527174"};


  exp_int::xubintvec modadd3;
  modadd3 = {
    "732016832092609303033733946488851575508905224089926209249817078392018535656765998725014589313481039123037168472673687025432538609494741909227605490712",
    "1699342641679108265957658838484592424389901138210036584743655868072997162880915829271284796618161346407552961175240302978676734578936494043850964404405",
    "805268194532540254853221827315978332231079936014530430473277788624701006514735685778788450107791579012474778927303995844441006517704086579510924761862",
    "2309639787857591865810616858010749359723574390920875954217594558571830391533743872493637498240411933565079085036268433921366315257151622475294470987432",
    "1055195209860101268914836871873995113935083573879425166713353648336452849248093827352855861589603089346167525745353916089497326627735522601358120785649",
    "2079272278780507283826438187565711365662706106566241503594152379685216330309021278700545062992019577249504763265865102246737159166053065841450634441253",
    "1963961166839109935958630686427211631758268415664486282780692695470499499487186103469461604166903659582068706589022694543822554406981111684423535524192",
    "429450322550600283289891166311775461461030276309914725166992747749473739737643236568408402032463028150942488266038351241904353417501229826560720600164",
  };

  exp_int::xubintvec modsub3;
  modsub3 = {
    "512597535603578636284620600471706441361256218177317597892343972007351046282937957699448030289016340695226985347494856694864680738501332532337154369965",
    "1258144990936911203380326908782167797434418468585961447166768171869509300176263104307921352873859541990711881935956355186437373393544036099224330319773",
    "805842730693986557467234043205212783543391008567040812905713540778130676580166107684104083420854024129298497671985888277617739050093011724484112870671",
    "2799309032266742562930769261070482408568899000258495476312314409719714580243471729247586479328620187276945241504429920336345307950164925099894493715533",
    "2647685260134934808804103597318860343122424407427906327669059277239997218032517842675609320811641720285003894680481883735468131235997696534443428488350",
    "693199162376459329128054716987553648346475871132117743341660758355345058542390369742037372302879022664441864154051826106098140959002251215605319777078",
    "2391797749376600579441197977047078160791084122445638582872412922268196751328156295695665483217670569843215892375267224089848674446364986290845863213758",
    "165016581053646305583802200792684936229797960441655784909448934591271278356760823782530076253342418118532753950587932901212416719129878255565055545816",
  };

  exp_int::xubintvec modmul3;
    modmul3 = {
    "1031054745145843056820705945780914118282144310817341310210020640625431998591940403233545109350272933868060509405157360000389345101372898822036359679625",
    "39893990336327654775086201222472749396440031633689107793562292818341559091551650098949141027412374031231642492390533436782802979527602128674296589001",
    "1281575364673380787247887100773933340217543950815953588352031340354110014040347164387450177246143958852636145466379632479296531828035602618716943463922",
    "8876626876958332707488109358602242636976932642794865821404042110211562924605397999217054754859843534043902943791892973269404255881395585577402022234",
    "1216222886905600696846574145744495331189790230286057979942862366975568127231919204120976315097923349074161373380531458334894968146858459205019035261534",
    "753004725575957473234700352714317139479193934162886068369016394155680048439319699359431951178436867519868720662245420487511271148333130090416613227734",
    "2781700410947724700353568488987777429973246834920346616320143955645243949889536315043352628634199412806795883041065539549687937536501039961931401092055",
    "477574462920419903543345320561430691498452711801747910227743781056369739411065806345235440677935972019383967954633150768168291144898135169751571023658",
  };

  exp_int::xubintvec c3;

  //now Mod operations
  c3 = a3.ModAdd(b3,q3);
  EXPECT_EQ (c3, modadd3) << "Failure big number vector vector ModAdd()";    
  
  c3 = a3.ModSub(b3,q3);
  EXPECT_EQ (c3, modsub3) << "Failure big number vector vector ModSub()";   
  
  c3 = a3.ModMul(b3,q3);
  EXPECT_EQ (c3, modmul3) << "Failure big number vector vector ModMul()";   
  
}

