#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Copyright (c) 2019, Erik Stites (aka Noah Buddy)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

Neither the name of the the copyright holder nor the names of
contributors to this software may be used to endorse or promote products
derived from this software without specific prior written permission. 

THIS CODE IS DISTRIBUTED IN THE HOPE THAT IT WILL BE USEFUL AND/OR ENTERTAINING,
BUT IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, CONSEQUENTIAL OR IMAGINED
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""
"The Greater Than Two Dimensional Cubic Cipher"


Not production ready. Use at your own risk.


Encode data using an N+2 dimensional 'Rubik's Cube' as a cipher mechanism
"""

import numpy as np
from hashlib import sha256

ENCODE = 1
DECODE = -1
SHIFT_CHANCE = 0.1


class NPRandEngine:
    """
    Request pseudo random numbers from this class.
    Generated numbers are from a group of PRNGs.
    Each request selects the next in the group to generate.
    Expects 'seeds' to be an array or list of 32 bit ints
    """
    def __init__(self, seeds):
        self.qty = len(seeds)
        self.select = 0
        self.genset = [ np.random.RandomState(sed & 0xFFFFFFFF) for sed in seeds ]
    
    def nextInt(self, bound):
        """
        Call this to get the next pseudo random integer
        Input-
            bound: range of result, from zero to bound (exclusive)
        Returns-
            Generated number
        """
        n = self.genset[self.select].randint(bound)
        self.select = (self.select + 1) % self.qty
        return n
    
    def choice(self, nmax, qty):
        grp = self.genset[self.select].choice(nmax, qty, False)
        self.select = (self.select + 1) % self.qty
        return grp
    
    def yesOrNo(self, chance=0.5):
        tst = True if self.genset[self.select].random_sample() > (1.0 - chance) else False
        self.select = (self.select + 1) % self.qty
        return tst



def getSideLengthFromDataSizeAndDims(datalen, dims, bitwise=True):
    """
    Find minimum side of 'dims' dimensional cube to fit
    'dat' and message length info (as bits)
    Input-
        datalen: length of data to be encoded
        dims: how many dimensions for this cube
        bitwise: select the size of array depending if data will be bits or bytes
    Returns-
        length of each side of desired cube
    """
    d = (datalen + 4) * (8 if bitwise else 1)
    pwr = np.power(d, 1.0/dims)
    L = np.ceil( pwr )
    return int(L)



def findDenseDimensionsFromDataSize(datalen, default_dims=3, allow_binary=False, bitwise=True):
    """
    Find the shape of data (dimensions and side length)
    that will result in the most efficient use of space while working
    This does not necessarily mean a better cipher
    Inputs-
        datalen: length of data to be encoded
        default_dims: optional, probably not necessary
            if for some reason, this calculation fails, use this value
        allow_binary: optional, by default will not choose a dimension where
            each side length is 1 (aka Binary)
        bitwise: select the size of array depending if data will be bits or bytes
    Returns-
        Shape of desired cube, length of each side and dimensions 
    """
    if allow_binary:
        OPT_BINARY = 1
    else:
        OPT_BINARY = 0
    
    MAXIMUM_DIFFERENCE = 1000000 # some large number
    bitlen = (datalen + 4) * (8 if bitwise else 1)
    print "bitlen: ", bitlen
    
    smallest_dif = MAXIMUM_DIFFERENCE # not likely
    best_dim = default_dims
    best_side = np.ceil(np.power(bitlen, 1.0/best_dim))
    print "bit len:", bitlen
    # at this point it is just binary...
    max_dims = int(np.ceil(np.log(bitlen) / np.log(2)))
    # it would take very many random scrambles to significantly mix the data 
    #print "max dims:", max_dims
    for dim in xrange(3, max_dims + OPT_BINARY): # Make 'going-binary' a choice
        test_side = np.ceil(np.power(bitlen, 1.0/dim))
        test_bound = test_side**dim
        dif = abs(test_bound - bitlen)
        #print "test side:", test_side, " test dim:", dim, " test bound:", test_bound, " dif:", dif
        if (test_bound > bitlen) and (smallest_dif > dif):
            best_side = test_side
            best_dim = dim
            smallest_dif = dif
    
    return int(best_side), int(best_dim)



# Relying on SHA256
def initGenerators(key):
    #global gensets
    h = sha256()
    h.update(key)
    hexed = h.hexdigest()
    SEED_LENGTH = 16 # hex characters
    seeds = [int(hexed[i:i+SEED_LENGTH], 16) for i in xrange(0, len(hexed), SEED_LENGTH)]
    generator = NPRandEngine( seeds )
    return generator



def getMappingNPMechanic(dims, side, gens, scramble_count=None):
    """
    (Pseudo) Randomly rotate 'slices' through a 'dims' dimensional
        cube with a side length of 'side', occasionally _shift_
        entire cube by a generated number of steps
        Uses Numpy library to perform array operations
        Generated 'addr' is initially sequential, will
            contain the mapping to place bits/bytes into the
            scrambled cube
    Inputs:
        dims: number of dimensions the cube has
        side: length of a side in each dimension
        gens: set of PRNGs used to scramble the cube
        scramble_count: specify number of scrambles
                        default to 3 times size of the data length
    Returns:
        An np array with the dims-dimensional cube
            containing the new locations
    """
    #D, S = 3, 3
    totalsize = side**dims
    structure = [side]*dims
    if scramble_count is not None:
        max_cycles = scramble_count
    else: # default behavior
        max_cycles = totalsize * 3 # for lack of a better method to choose scrambles
    
    #gen = np.random.RandomState(42)
    block = np.arange(totalsize)
    block.shape = structure
    ind=[slice(None)]*dims
    shiftcounter = 0
    for cycles in xrange(max_cycles):
        # Minimizes number of shifts and focus on rotations
        if gens.yesOrNo(SHIFT_CHANCE):
            steps = gens.nextInt(side)
            ax = gens.nextInt(dims)
            block = np.roll(block, steps, axis=ax)
            shiftcounter += 1
        else:
            ax, ay, az = gens.choice(dims,3)
            for n in xrange(dims):
                ind[n] = gens.nextInt(side)
            
            ind[ax] = ind[ay] = slice(None)
            ind[az] = slice(ind[az], side)
            tb = block[tuple(ind)]
            ts = tb.shape
            # Find equal sides of ts and rotate by those
            # ts will always be 3 dimensional, sides will always be LT or EQ
            # An IF test will have slightly different results than the sort method
            #   due to order of operations: if the first are equal, do something
            #   the next two might also be equal
            idx = np.argsort(ts) # to be concise
            rot = (idx[1], idx[2])
            
            block[tuple(ind)] = np.rot90(tb, 1, rot)
    
    block.shape = (totalsize)
    print shiftcounter, " / ", max_cycles
    return block



def codecode(mapping, inp, outp, codec=ENCODE):
    """
    Place bits/bytes from data into cipher cube or reverse
    Inputs-
        mapping: locations to put data
            inp[i] from data will be placed at out[mapping[i]] if encoding
            inp[mapping[i]] from data will be placed at outp[i] if decoding
        inp: data to move
        outp: data in new locations
    Returns-
        Nothing, outp[] contains result
    """
    #print "cmp len:", len(mapping), len(inp), len(outp)
    if codec == ENCODE:
        for i in xrange(len(mapping)):
            outp[mapping[i]] = inp[i]
    else:
        for i in xrange(len(mapping)):
            outp[i] = inp[mapping[i]]


"""
Using Numpy methods, there may be better ways construct/deconstruct the bit arrays
"""
def encodebitwise(key, dat, dimensions=None, toArray=False, xoraddrs=True):
    """
    Use the >2D Cubic Cipher to encode a message
    Inputs-
        key: user input, password
        dat: user data to encode
        dimensions: optional, user can specify dims
            otherwise function will select
        toArray: optional, user can specify either byte array or string
            as result
        xoraddrs: optional, specify if output bytes are XOR'd with
            the values of shuffled locations, default (True) is used
    Returns-
        A Tuple containing:
            Encoded data as either byte array (chosen with toArray=True)
                or a string (default)
            Side length of Cubic Cipher
            Dimensions of Cubic Cipher
    """
    vals = np.frombuffer(dat, dtype='>u1')
    #print type(vals)
    #print vals, type(vals[0])
    
    if dimensions is not None:
        sidel = getSideLengthFromDataSizeAndDims(len(vals), dimensions, bitwise=True)
        dim = dimensions
    else:
        sidel, dim = findDenseDimensionsFromDataSize(len(dat), bitwise=True)

    fullsz = sidel**dim
    gens = initGenerators(key)
    dst = np.zeros(fullsz, dtype=np.uint8)
    addrs = np.arange(0, fullsz)
    addrs = getMappingNPMechanic(dim, sidel, gens)
    
    L = len(dat)
    
    nz = np.array([L], dtype='>u4').tostring() #tobytes() # Watch for rev of Numpy
    sz = np.frombuffer(nz, dtype='>u1')
    
    lenbits = np.unpackbits(np.array(sz, dtype=np.uint8))
    valbits = np.unpackbits(np.array(vals, dtype=np.uint8))
    
    databits = np.zeros(fullsz, dtype=np.uint8)
    # these loops could be made into slice-indexed assignment statements
    for n in xrange(len(valbits)):
        databits[n] = valbits[n]

    for n in xrange(len(lenbits)): # support for an uint32 to represent the length
        databits[fullsz-n-1] = lenbits[n] # fills bits in reverse order

    codecode(addrs, databits, dst, codec=ENCODE)
    if xoraddrs:
        dst ^= np.array(addrs & 1, dtype=np.uint8)
    
    encodedbytes = np.packbits(dst)
    encoded = encodedbytes.tostring() #tobytes() # make it a string
    
    if toArray:
        return encodedbytes, sidel, dim
    else:
        return encoded, sidel, dim





def encode(key, dat, dimensions=None, toArray=False, xoraddrs=True, sizeplaceholder=False):
    """
    Use the >2D Cubic Cipher to encode a message
    Inputs-
        key: user input, password
        dat: user data to encode
        dimensions: optional, user can specify dims
            otherwise function will select
        toArray: optional, user can specify either byte array or string
            as result
        xoraddrs: optional, specify if output bytes are XOR'd with
            the values of shuffled locations, default (True) is used
        sizeplaceholder: used for debugging. fill in the four bytes
            holding the original length with 0-3 inclusive.
            WARNING: This will crash decoding
    Returns-
        A Tuple containing:
            Encoded data as either byte array (chosen with toArray=True)
                or a string (default)
            Side length of Cubic Cipher
            Dimensions of Cubic Cipher
    """
    vals = np.frombuffer(dat, dtype='>u1').astype(np.uint8)
    #print type(vals)
    #print "vals: ", vals, type(vals[0])
    
    if dimensions is not None:
        sidel = getSideLengthFromDataSizeAndDims(len(vals), dimensions, bitwise=False)
        dim = dimensions
    else:
        sidel, dim = findDenseDimensionsFromDataSize(len(dat), bitwise=False)
    
    fullsz = sidel**dim
    gens = initGenerators(key)
    dst = np.zeros(fullsz, dtype=np.uint8)
    addrs = np.arange(0, fullsz)
    addrs = getMappingNPMechanic(dim, sidel, gens)
    
    L = len(dat)
    
    print "L:", L, "fullsz:", fullsz
    
    nz = np.array([L], dtype=np.uint32) #tobytes() # Watch for rev of Numpy
    nz.dtype = np.uint8
    
    databytes = np.array([ord(' ')]*fullsz, dtype=np.uint8)
    
    # these loops could be made into slice-indexed assignment statements
    for n in xrange(len(vals)):
        databytes[n] = vals[n]

    for n in xrange(len(nz)): # support for an uint32 to represent the length
        if not sizeplaceholder:
            databytes[fullsz-n-1] = nz[n] # fills bits in reverse order
        else:
            databytes[fullsz-n-1] = n+ord('0')
            #print chr(n+ord('0'))
    
    codecode(addrs, databytes, dst, codec=ENCODE)
    
    #print databytes
    
    print len(dst)
    
    if xoraddrs:
        dst ^= np.array(addrs & 255, dtype=np.uint8) # bitwise mask of locations (do not &1 if using full bytes)
    
    encodedbytes = dst
    encoded = dst.tostring() #tobytes() # make it a string
    
    if toArray:
        return encodedbytes, sidel, dim
    else:
        return encoded, sidel, dim



def decodebitwise(key, dat, dimensions, sidelength, toArray=False, xoraddrs=True):
    """
    Use the >2D Cubic Cipher to encode a message
    Inputs-
        key: user input, password
        dat: encoded data
        dimensions: required, shape of encoded cube must be known to decode
        sidelength: required, shape of encoded cube must be known to decode
        toArray: optional, user can specify either byte array or string
            as result, default (False) returns a string
        xoraddrs: optional, specify if output bytes are XOR'd with
            the values of shuffled locations, default (True) is used
    Returns-
        Decoded data as either byte array (chosen with toArray=True)
            or a string (default)
    """
    extracted = np.frombuffer(dat, dtype='>u1')
    
    print "extract:", extracted #, " len:", len(extracted)
    fullsz = sidelength**dimensions
    addrs = np.arange(0, fullsz)
    dst = np.zeros(fullsz, dtype=np.uint8)
    gens = initGenerators(key)
    addrs = getMappingNPMechanic(dimensions, sidelength, gens)
    block = np.unpackbits(extracted)
    exactblock = block[:fullsz]
    
    if xoraddrs:
        exactblock ^= np.array(addrs & 1, dtype=np.uint8)
    
    codecode(addrs, exactblock, dst, codec=DECODE)
    
    recoveredlength = np.frombuffer(np.packbits(dst[-1:-33:-1]), dtype='>u4')[0]
    decodedbytes = np.packbits(dst[:recoveredlength*8])
    decoded =  np.frombuffer(decodedbytes, dtype='>u1').tostring() #tobytes()
    
    if toArray:
        return decodedbytes
    else:
        return decoded




def decode(key, dat, dimensions, sidelength, toArray=False, xoraddrs=True):
    """
    Use the >2D Cubic Cipher to encode a message
    Inputs-
        key: user input, password
        dat: encoded data
        dimensions: required, shape of encoded cube must be known to decode
        sidelength: required, shape of encoded cube must be known to decode
        toArray: optional, user can specify either byte array or string
            as result
    Returns-
        Decoded data as either byte array (chosen with toArray=True)
            or a string (default)
    """
    extracted = np.frombuffer(dat, dtype='>u1').astype(np.uint8)
    
    print "extract:", extracted #, " len:", len(extracted)
    fullsz = sidelength**dimensions
    addrs = np.arange(0, fullsz)
    dst = np.zeros(fullsz, dtype=np.uint8)
    gens = initGenerators(key)
    addrs = getMappingNPMechanic(dimensions, sidelength, gens)
    #block = np.unpackbits(extracted)
    exactblock = extracted # block[:fullsz]
    
    if xoraddrs:
        exactblock ^= np.array(addrs & 255, dtype=np.uint8) # bitwise mask of locations
    
    codecode(addrs, exactblock, dst, codec=DECODE)
    
    #recoveredlength = np.frombuffer(np.packbits(dst[-1:-33:-1]), dtype='>u4')[0]
    #decodedbytes = np.packbits(dst[:recoveredlength*8])
    #decoded =  np.frombuffer(decodedbytes, dtype='>u1').tostring() #tobytes()
    
    Lbuff = np.copy(dst[-1:-5:-1])
    Lbuff.dtype = np.uint32
    recoveredlength = Lbuff[0]
    
    decodedbytes = dst[:recoveredlength]
    decoded =  decodedbytes.tostring() #tobytes()
    
    
    if toArray:
        return decodedbytes
    else:
        return decoded


##
#  TODO:
#
#       Figure out how to choose a 'good' number of iterations <----
#
#       Mark beginning of file with 2 bytes, hex value of 'C00B'
#           Save converted bytes, dimension, and side length to file...
#           reverse to decode
#
#       Put all into a class
#


if __name__ == '__main__':
    
    orig = """AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"""
    
    #orig = 'A'*64
    #orig = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    #orig = 'How much wood could a woodchuck chuck if a woodchuck could chuck wood?'
    #orig = 'abcdefghijklmnopqrstuvwxyz'
    
    
    #passkey = 'It was going to be taco Tuesday.'
    #passkey = '12345password'
    #passkey = 'Woodchuck'
    #passkey = '1'
    #passkey = 'b'
    passkey = 'c'
    
    '''
    # need to know the shape of encoding to decode
    output, sidelen, N = encode(passkey, orig)
    
    ## TODO: write dimensions, side length and data to file
    #
    # Optionally use output length and a similar function to
    # findDenseDimensionsFromDataSize() to calculate shape
    #
    
    print output
    txt = ""
    for c in output:
        txt += "{:02x}".format(ord(c))
    print "encoded length:", len(output)
    print "dims:", sidelen, "|", N
    print txt
    
    
    decodeddata = decode(passkey, output, N, sidelen) #, toArray=True
    
    print decodeddata
    '''
    
    
    
    """
    mix, sidelen, N = encodebitwise(passkey, orig, toArray=False, xoraddrs=True)
    print mix
    
    decodeddata = decodebitwise(passkey, mix, N, sidelen, toArray=False, xoraddrs=True)
    print decodeddata
    """
    
    # decode does not work with placeholders
    mix, sidelen, N = encode(passkey, orig, toArray=False, xoraddrs=False, sizeplaceholder=False)
    print mix
    
    txt = ""
    for c in mix:
        txt += "{:02x}".format(ord(c))
    print "encoded length:", len(mix)
    print "dims:", sidelen, "|", N
    print txt
    
    
    decodeddata = decode(passkey, mix, N, sidelen, toArray=False, xoraddrs=False)
    print decodeddata
    


