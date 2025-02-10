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

class BBS_DAA_A(ABEnc):         
    def __init__(self, group_obj, verbose = False):
        ABEnc.__init__(self)
        self.name = "BBS-based DAA-A"
        self.group = group_obj       

    def Setup(self, L):        
        # Set the maximum number of attributes
        L = L
        
        # pick generators     
        g, g0, H = self.group.random(G1), self.group.random(G1), self.group.random(G1)      
        g_hat = self.group.random(G2)
        
        Gp1 = []      

        for i in range(L):                    
            Gp1.append(self.group.random(G1))
                                    
        pp = {'g': g, 'g0': g0, 'Gp1': Gp1, 'H': H, 'g_hat': g_hat, 'L': L}
        return pp
 
    def CAKeyGen(self, pp):
        # Choose issuer (CA) secret key and public key
        x = self.group.random(ZR)
        
        X_hat = pp['g_hat'] ** x

        mpk = X_hat
        msk = x
        
        # Compute NIZKP for mpk X and Y
        alpha = self.group.random(ZR)      
        c = self.group.hash(str(X_hat) + str(pp['g_hat'] ** alpha), ZR)        
        s = alpha - c * x       
        
        piI = {'c': c, 's': s}

        return mpk, msk, piI
        
    def UKeyGen(self, pp, mpk, piI):
        # Verify the NIZKP piI
        verify = 0
        if piI['c'] == self.group.hash(str(mpk) + str(mpk ** piI['c'] * pp['g_hat'] ** piI['s']), ZR):
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
        
        E = self.group.random(ZR)
        
        A = (pp['g0'] * upk) ** (1 / (msk + E))
        
        cre = {'A': A, 'E': E}
        
        return cre
                      
    def anonPre(self, pp, cre, mpk, upk, usk, msg): 
        # The signer verifies the certificate from the issuer
        verify = 0
        if pair(cre['A'], mpk * pp['g_hat'] ** cre['E']) == pair(pp['g0'] * upk, pp['g_hat']):
            #print('The user certificate is correct!')
            verify += 1
        else: 
            #print('The user certificate is wrong!')
            verify += 0 
        
        # Blind the certificate        
        n = self.group.random(ZR)
        
        A_prime = cre['A'] * pp['H'] ** n
                
        # Calculate the commit values for unlinked attributes
        R, W2 = [], []
        
        for i in range(pp['L']):
            w = self.group.random(ZR)
            r = pp['Gp1'][i] ** w
            W2.append(w)            
            R.append(r)
           
        # Calculate a ZKP
        alpha, beta, gamma = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        
        prod = 1
        for i in range(pp['L']):
            prod *= R[i]
        
        mu = pair(pp['H'] ** alpha, mpk)
        omega = pair(A_prime ** beta * pp['H'] ** gamma * prod, pp['g_hat'])
        
        concatenate = str(mu * omega)                
        concatenate += msg
        
        c = self.group.hash(concatenate, ZR)
        
        s_alpha = alpha - c * n
        s_beta = beta + c * cre['E']
        s_gamma = gamma - c * n * cre['E']
        
        s2 = []        
        for i in range(pp['L']):
            s2.append(W2[i] - c * usk[i])
        
        sigma = {'A_prime': A_prime, 'c': c, 's_alpha': s_alpha, 's_beta': s_beta, 's_gamma': s_gamma, 's2': s2}
        
        return sigma
        
    def aVerify(self, pp, mpk, sigma, msg):
        # Check every verification step 
        verify = 0
        
        prod = 1
        for i in range(pp['L']):
            prod *= pp['Gp1'][i] ** sigma['s2'][i]
                      
        mu_prime = pair(sigma['A_prime'] ** sigma['c'] * pp['H'] ** sigma['s_alpha'], mpk)
        omega_prime = pair(sigma['A_prime'] ** sigma['s_beta'] * pp['H'] ** sigma['s_gamma'] * prod * (1/ pp['g0'] ** sigma['c']), pp['g_hat'])
                
        concatenate = str(mu_prime * omega_prime)            
        concatenate += msg
        
        if sigma['c'] == self.group.hash(concatenate, ZR):
            #print('The fourth step is correct!')
            verify += 1
        else: 
            #print('The fourth step is wrong!')    
            verify += 0
            
        if verify == 1:
            #rint('All the verifications are passed!!!')
            return 1
        else:
            #print('Some steps are not passed.')
            return 0
                     



   

        
        
        
        
        
        
        
            
            
            
            
            
            
              
