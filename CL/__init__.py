'''
Liqun Chen and Rainer Urian

| From: "DAA-A: Direct Anonymous Attestation with Attributes"
| type:           DAA-A
| setting:        Type-III Pairing

:Authors:         Long Meng
:Date:            12/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
import re, numpy, hashlib

debug = False

class CL_DAA_A(ABEnc):         
    def __init__(self, group_obj, verbose = False):
        ABEnc.__init__(self)
        self.name = "CL-based DAA-A"
        self.group = group_obj       

    def Setup(self, L):        
        # Set the maximum number of attributes
        L = L
        
        # pick generators     
        g1, g2 = self.group.random(G1), self.group.random(G2)     
        
        Gp1, Gp2 = [], []      

        for i in range(L):         
            r = self.group.random(ZR)
            Gp1.append(g1 ** r)
            Gp2.append(g2 ** r)          
                
        pp = {'g1': g1, 'g2': g2, 'Gp1': Gp1, 'Gp2': Gp2, 'L': L}
        return pp
 
    def CAKeyGen(self, pp):
        # Choose issuer (CA) secret key and public key
        x, y = self.group.random(ZR), self.group.random(ZR)
        
        X = pp['g2'] ** x
        Y = pp['g2'] ** y
            
        mpk = {'X': X, 'Y': Y}     
        msk = {'x': x, 'y': y}
        
        # Compute NIZKP for mpk X and Y
        alpha, beta = self.group.random(ZR), self.group.random(ZR)       
        c = self.group.hash(str(X) + str(pp['g2'] ** alpha) + str(Y) + str(pp['g2'] ** beta), ZR)        
        s_x = alpha - c * x
        s_y = beta - c * y
        
        piI = {'c': c, 's_x': s_x, 's_y': s_y}

        return mpk, msk, piI
        
    def UKeyGen(self, pp, mpk, piI):
        # Verify the NIZKP piI
        verify = 0
        if piI['c'] == self.group.hash(str(mpk['X']) + str(mpk['X'] ** piI['c'] * pp['g2'] ** piI['s_x']) + str(mpk['Y']) + str(mpk['Y'] ** piI['c'] * pp['g2'] ** piI['s_y']), ZR):
            #print('The NIZKP piI is correct!')
            verify += 1
        else: 
            #print('The NIZKP piI is wrong!')
            verify += 0             
        
        # Choose user secret key and public key
        usk = []
        upk = 1
        for i in range(pp['L']):
            x = self.group.random(ZR)
            usk.append(x)  
            upk *= pp['Gp1'][i] ** x        
        
        # Calculate a Schnorr ZKP for upk
        prod = 1
        lamb = []
        for i in range(pp['L']):
            lamb.append(self.group.random(ZR))
            prod *= pp['Gp1'][i] ** lamb[i]
        
        c = self.group.hash(str(upk) + str(prod), ZR)
        
        s = []        
        for i in range(pp['L']):
            s.append(lamb[i] - c * usk[i])
        
        pi = {'c': c, 's': s}
        
        return upk, usk, pi

    def randCre(self, pp, msk, upk, pi, msg):
        # Verify the ZKP pi
        prod = 1
        for i in range(pp['L']):
            prod *= pp['Gp1'][i] ** pi['s'][i]
        
        verify = 0
        if pi['c'] == self.group.hash(str(upk) + str(upk ** pi['c'] * prod), ZR):
            #print('The NIZKP pi is correct!')
            verify += 1
        else: 
            #print('The NIZKP pi is wrong!')
            verify += 0        
        # Calculate A, B, C, D, E
        r = self.group.random(ZR)
        
        A = pp['g1'] ** r
        B = A ** msk['y']  
        C = A ** msk['x'] * upk ** (r * msk['x'] * msk['y'])
        D = upk ** (r * msk['y'])
        E = []
        
        for i in range(pp['L']):
            e = pp['Gp1'][i] ** (r * msk['y'])
            E.append(e)
            
        # Calculate a Schnorr ZKP    
        w = self.group.random(ZR)
        
        concatenate = str(pp['g1'] ** w)
       
        for i in range(pp['L']):
            concatenate += str(pp['Gp1'][i] ** w)
        
        concatenate += str(upk ** w) + msg
        
        c_hat = self.group.hash(concatenate, ZR)
        s_hat = w - c_hat * r * msk['y']
        
        cre = {'A': A, 'B': B, 'C': C, 'D': D, 'E': E, 'c_hat': c_hat, 's_hat': s_hat}
        
        return cre
                      
    def anonPre(self, pp, cre, mpk, upk, usk, msg): 
        # The signer verifies the certificate from the issuer
        verify = 0
        if pair(cre['A'], mpk['Y']) == pair(cre['B'], pp['g2']):
            #print('Step 1 is correct!')
            verify += 1
        else: 
            #print('Step 1 is wrong!')
            verfiy += 0

        if pair(cre['A'] * cre['D'], mpk['X']) == pair(cre['C'], pp['g2']):
            #print('Step 2 is correct!')
            verify += 1
        else:
            #print('Step 2 is wrong!')
            verfiy += 0
            
        concatenate = str(cre['B'] ** cre['c_hat'] * pp['g1'] ** cre['s_hat'])
        
        for i in range(pp['L']):
            concatenate += str(cre['E'][i] ** cre['c_hat'] * pp['Gp1'][i] ** cre['s_hat'])   
            
        concatenate += str(cre['D'] ** cre['c_hat'] * upk ** cre['s_hat']) + msg
        
        if cre['c_hat'] == self.group.hash(concatenate, ZR):
            #print('Step 3 is correct!')
            verify += 1
        else: 
            #print('Step 3 is wrong!')   
            verify += 0
        
        # Blind the modified CL certificate        
        a = self.group.random(ZR)
        
        A_prime = cre['A'] ** a
        B_prime = cre['B'] ** a
        C_prime = cre['C'] ** a
        D_prime = cre['D'] ** a
        E_prime = []
        for i in range(pp['L']):
            E_prime.append(cre['E'][i] ** a)
        
        # Calculate the commit values for unlinked attributes
        R, W2 = [], []
        
        for i in range(pp['L']):
            w = self.group.random(ZR)
            r = E_prime[i] ** w
            W2.append(w)            
            R.append(r)
           
        # Calculate a ZKP
        concatenate = str(A_prime) + str(B_prime) + str(C_prime) + str(D_prime)
        
        for i in range(pp['L']):
            concatenate += str(E_prime[i])
        
        mul = 1
        for i in range(len(R)):
            mul *= R[i] 
        
        concatenate += str(mul)               
        concatenate += msg
        
        c = self.group.hash(concatenate, ZR)
        
        s2 = []        
        for i in range(pp['L']):
            s2.append(W2[i] - c * usk[i])
        
        sigma = {'A_prime': A_prime, 'B_prime': B_prime, 'C_prime': C_prime, 'D_prime': D_prime, 'E_prime': E_prime, 'c': c, 's2': s2}
        
        return sigma
        
    def aVerify(self, pp, mpk, sigma, msg):
        # Check every verification step 
        verify = 0
        if pair(sigma['A_prime'], mpk['Y']) == pair(sigma['B_prime'], pp['g2']):
            #print('The first step is correct!')
            verify += 1
        else: 
            #print('The first step is wrong!')
            verify += 0
            
        if pair(sigma['A_prime'] * sigma['D_prime'], mpk['X']) == pair(sigma['C_prime'], pp['g2']):        
            #print('The second step is correct!')
            verify += 1
        else: 
            #print('The second step is wrong!')     
            verify += 0   
        
        mul1 = 1
        mul2 = 1
        mul3 = 1
        for i in range(pp['L']):
            t = self.group.random(ZR)
            mul1 *= sigma['E_prime'][i] ** t
            mul2 *= pp['Gp2'][i] ** t
            mul3 *= sigma['E_prime'][i] ** sigma['s2'][i]
            
        if pair(mul1, pp['g2']) == pair(sigma['B_prime'], mul2):
            #print('The third step is correct!')
            verify += 1
        else: 
            #print('The third step is wrong!') 
            verify += 0             
        
        mu = sigma['D_prime'] ** sigma['c'] * mul3 
                
        concatenate = str(sigma['A_prime']) + str(sigma['B_prime']) + str(sigma['C_prime']) + str(sigma['D_prime'])
        
        for i in range(pp['L']):
            concatenate += str(sigma['E_prime'][i])

        concatenate += str(mu)       
        concatenate += msg
        
        if sigma['c'] == self.group.hash(concatenate, ZR):
            #print('The fourth step is correct!')
            verify += 1
        else: 
            #print('The fourth step is wrong!')    
            verify += 0
            
        if verify == 4:
            #print('All the verifications are passed!!!')
            return 1
        else:
            #print('Some steps are not passed.')
            return 0
                     



   

        
        
        
        
        
        
        
            
            
            
            
            
            
              
