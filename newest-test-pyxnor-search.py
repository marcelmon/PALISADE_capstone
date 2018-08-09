# dBKeyBitsAndValues 	= [[[keybits],value],...]
# queryKeyBits 		= []

from functools import reduce

keyOneBits 		= [0,0]
keyOneValue 	= 1

keyTwoBits 		= [0,1]
keyTwoValue 	= 2

keyThreeBits 	= [1,0]
keyThreeValue 	= 3

keyFourBits 	= [1,1]
keyFourValue 	= 4

queryKeyBits 	= [0,1]



dBKeyBitsAndValues 	= [[keyOneBits,keyOneValue], [keyTwoBits,keyTwoValue], [keyThreeBits,keyThreeValue], [keyFourBits,keyFourValue]]

oneVal = 1

negOneVal = -1

def add(one, two):
	return one + two

def mult(one, two):
	return one * two

def sub(one, two):
	return add(one, (mult(two, negOneVal)))

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

print("a res key one")
print(doBinaryXnorBit(0,0))

print("a res 0 1")
print(doBinaryXnorBit(0,1))

print("a res 1 0")
print(doBinaryXnorBit(1,0))

print("a res 1 1")
print(doBinaryXnorBit(1,1))


# print(map(lambda dbKeyAndVal: doKeyXnor(dbKeyAndVal[0], queryKeyBits), dBKeyBitsAndValues))

def doKeyXnor(dbKeyBits):
	return reduce(mult, map(lambda x, queryKeyBits=queryKeyBits: doBinaryXnorBit(x[0],x[1]), zip(dbKeyBits, queryKeyBits)))


print("NEXT")

print("a res [0,0] [0,1]")
print(doKeyXnor([0,0]))

print("a res [0,1] [0,1]")
print(doKeyXnor([0,1]))

print("a res [1,0] [0,1]")
print(doKeyXnor([1,0]))

print("a res [1,1] [0,1]")
print(doKeyXnor([1,1]))


def doKeyAndValueXnor(dbKeyBitsAndValue):
	return mult(doKeyXnor(dbKeyBitsAndValue[0]), dbKeyBitsAndValue[1])


print("NEXT")

print("a res [[0,0],1] [0,1]")
print(doKeyAndValueXnor([[0,0],1]))

print("a res [[0,1],2] [0,1]")
print(doKeyAndValueXnor([[0,1],2]))

print("a res [[1,0],3] [0,1]")
print(doKeyAndValueXnor([[1,0],3]))

print("a res [[1,1],4] [0,1]")
print(doKeyAndValueXnor([[1,1],4]))


print("NEXT3")

print("a res [[0,0],1] [0,1]")
print(doKeyAndValueXnor(dBKeyBitsAndValues[0]))

print("a res [[0,1],2] [0,1]")
print(doKeyAndValueXnor(dBKeyBitsAndValues[1]))

print("a res [[1,0],3] [0,1]")
print(doKeyAndValueXnor(dBKeyBitsAndValues[2]))

print("a res [[1,1],4] [0,1]")
print(doKeyAndValueXnor(dBKeyBitsAndValues[3]))

def doAllKeyValueXnors(allDBKeyBitsAndValue):
	return reduce(add, map(doKeyAndValueXnor, allDBKeyBitsAndValue), 0)

print("last")

print("on [0,0] should be 1")
queryKeyBits = [0,0]
print(doAllKeyValueXnors(dBKeyBitsAndValues))
print("on [0,1] should be 2")
queryKeyBits = [0,1]
print(doAllKeyValueXnors(dBKeyBitsAndValues))
print("on [1,0] should be 3")
queryKeyBits = [1,0]
print(doAllKeyValueXnors(dBKeyBitsAndValues))
print("on [1,1] should be 4")
queryKeyBits = [1,1]
print(doAllKeyValueXnors(dBKeyBitsAndValues))
# # is used to make a copy of queryKeyBits for each dbKeyBitArray
# map(lambda keyBitsAndValue: mult(keyBitsAndValue[1],doKeyXnor(keyBitsAndValue[0], queryKeyBits), dBKeyBitsAndValues))



