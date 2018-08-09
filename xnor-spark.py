from functools import reduce

# dBKeyBitsAndValues 	= [[keyOneBits,keyOneValue], [keyTwoBits,keyTwoValue], [keyThreeBits,keyThreeValue], [keyFourBits,keyFourValue]]

# oneVal = 1

# negOneVal = -1



# serialized = example.Serialized()
# example.ReadSerializationFromFile(SparkFiles.get('cryptocontext.cc'), serialized)
# cryptoContext = example.CryptoContextFactory.DeserializeAndCreateContext(serialized, False)


import fhe


class XnorPYSpark(object):
	"""class to perform all fhe query operations"""
	def __init__(self, cryptoContext, pubkey, dbinfo):
		super(ClassName, self).__init__()
		self.cryptoContext 	= cryptoContext
		self.pubkey 		= pubkey
		self.dbinfo 		= dbinfo

		self.oneVal 	= cryptoContext.encrypt(cryptoContext, pubkey, 1)
		self.negOneVal 	= cryptoContext.encrypt(cryptoContext, pubkey, -1)

	def getAllDBKeyValueBitTuples():
		return (something with self.dbinfo)
	


	def add(one, two):
		return cryptoContext.EvalAdd(one, two)

	def mult(one, two):
		return cryptoContext.EvalMult(one, two)

	def sub(one, two):
		return cryptoContext.EvalAdd(one, (cryptoContext.EvalMult(two, self.negOneVal)))

	def doBinaryXnorBit(dbBit, queryBit):

		# A' = A - 1
		# B' = B - 1
		dbBitMinus1 	= sub(dbBit, oneVal)
		queryBitMinus1 	= sub(queryBit, oneVal)

		# C = (A x B)+(A' x B')
		xnorLeftResult 	= mult(dbBit, queryBit)
		xnorrightResult = mult(dbBitMinus1, queryBitMinus1)

		xnorResultBoth 	= add(xnorLeftResult, xnorrightResult)

		return xnorResultBoth

	# print(map(lambda dbKeyAndVal: doKeyXnor(dbKeyAndVal[0], queryKeyBits), dBKeyBitsAndValues))

	def doKeyXnor(dbKeyBits):
		return reduce(mult, map(lambda x, queryKeyBits=queryKeyBits: doBinaryXnorBit(x[0],x[1]), zip(dbKeyBits, queryKeyBits)))


	def doKeyAndValueXnor(dbKeyBitsAndValue):
		return mult(doKeyXnor(dbKeyBitsAndValue[0]), dbKeyBitsAndValue[1])

	def doAllKeyValueXnors(allDBKeyBitsAndValue):
		return reduce(add, map(doKeyAndValueXnor, allDBKeyBitsAndValue), 0)

	def queryAll(dBKeyBitsAndValues):
		# dBKeyBitsAndValues 	= [[keyOneBits,keyOneValue], [keyTwoBits,keyTwoValue], [keyThreeBits,keyThreeValue], [keyFourBits,keyFourValue]]

	queryKeyBits = [1,1]
	print(doAllKeyValueXnors(dBKeyBitsAndValues))
	# # is used to make a copy of queryKeyBits for each dbKeyBitArray
	# map(lambda keyBitsAndValue: mult(keyBitsAndValue[1],doKeyXnor(keyBitsAndValue[0], queryKeyBits), dBKeyBitsAndValues))



