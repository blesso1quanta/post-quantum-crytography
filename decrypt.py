import numpy as np
from math import log, gcd
import sys
from sympy import Poly, symbols
from NTRUutil import *
import sys
from os.path import exists

class NTRUdecrypt:

    """
    A class to decrypt data with the NTRU method.
    """


    def decrypt(self,e):
        """
        Decrypt the message given as in an input array e into the decrypted message m and return.
        """
        # The encrypted message e must have degree < N
        if len(e)>self.N:
            sys.exit("Encrypted message has degree > N")
        # Error checks passed, now decrypt and return as a np array
        x = symbols('x')
        a = ((Poly(self.f,x)*Poly(e,x))%Poly(self.I,x)).trunc(self.q)
        b = a.trunc(self.p)
        c = ((Poly(self.fp,x)*b)%Poly(self.I,x)).trunc(self.p)

        return np.array(c.all_coeffs(),dtype=int)


    def decryptString(self,E):
        """
        Decrypt a message encoded using the requisite public key from an encoded to a decoded string.
        """

        # First convert the string to a numpy
        Me = np.fromstring(E, dtype=int, sep=' ')
        # And check the input array is the correct length, i.e. an integer multiple of N
        if np.mod(len(Me),self.N)!=0:
            sys.exit("\n\nERROR : Input decrypt string is not integer multiple of N\n\n")

        # Now decrypt each block, appending to the message string
        Marr = np.array([],dtype=int)
        for D in range(len(Me)//self.N):
            Marr = np.concatenate((Marr,padArr(self.decrypt(Me[D*self.N:(D+1)*self.N]),self.N)))

        # And return the string decrypted
        self.M = bit2str(Marr)

    def readPriv(self,filename="NTRU_key.priv"):
        """
        Read a public key file
        """
        with open(filename,"r") as f:
            self.p  = int(f.readline().split(" ")[-1])
            self.q  = int(f.readline().split(" ")[-1])
            self.N  = int(f.readline().split(" ")[-1])
            self.df = int(f.readline().split(" ")[-1])
            self.dg = int(f.readline().split(" ")[-1])
            self.dr = int(f.readline().split(" ")[-1])
            tmp = f.readline()
            self.f  = np.array(f.readline().split(" "),dtype=int)
            self.fp = np.array(f.readline().split(" "),dtype=int)
            self.fq = np.array(f.readline().split(" "),dtype=int)
            self.g  = np.array(f.readline().split(" "),dtype=int)
        self.I         = np.zeros((self.N+1,), dtype=int)
        self.I[self.N] = -1
        self.I[0]      = 1

# Decrypt some data using the known private key

if not exists("NTRU_key.priv"):
    sys.exit("ERROR private key not found.")

e = input()
def decryption(encryptstring,filename="key.priv"):
    # First check if the private key file exists
    # Then initialise an decryption class
    D = NTRUdecrypt()

    # And read the public key
    D.readPriv("NTRU_key.priv")

    # Extract the data to decrypt
    to_decrypt = encryptstring

    D.decryptString(to_decrypt)
    print(D.M)


decryption(e,filename="NTRU_key.priv")

