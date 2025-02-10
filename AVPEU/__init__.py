'''
Yalan Wang, Liqun Chen, Yangguang Tian, Long Meng, Christopher Newton

| From: "AVPEU: Anonymous Verifiable Presentations with Extended Usability"
| type:           Anonymous DID and VC scheme based on PS signature
| setting:        Type-III Pairing

:Authors:         Long Meng
:Date:            08/08/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
import re, numpy, hashlib

debug = False

class AnonDID(ABEnc):         
    def __init__(self, group_obj, verbose = False):
        ABEnc.__init__(self)
        self.name = "Our scheme"
        self.group = group_obj       

    def Setup(self, L):
        # pick generators
        g2 = self.group.random(G2)
        L = L
        
        pp = {'g2': g2, 'L': L}
        return pp
 
    def CAKeyGen(self, pp):
        # Set y and Y as an empty arrays
        y, Y = [], []
        x = self.group.random(ZR)
        
        # Calculate X
        X = pp['g2'] ** x
        
        # Randomly choose elements y_1, ... y_L 
        for i in range(pp['L']):
            k = self.group.random(ZR)
            y.append(k)
            Y.append(pp['g2'] ** k)
            
        mpk = {'X': X, 'Y': Y}     
        msk = {'x': x, 'y': y}
        
        # Compute NIZKP for the mpk and msk
        alpha = self.group.random(ZR)
        X_prime = pp['g2'] ** alpha
        
        beta, Y_prime = [], []
        concatenate_Y = ''
        concatenate_Y_prime = ''
        for i in range(pp['L']):
            beta.append(self.group.random(ZR))
            Y_prime.append(pp['g2'] ** beta[i])
            concatenate_Y += str(Y[i])
            concatenate_Y_prime += str(Y_prime[i])
                
        c = self.group.hash(str(X) + str(X_prime) + concatenate_Y + concatenate_Y_prime, ZR)            
        s_x = alpha - c * x
                     
        s_y = []
        for i in range(pp['L']):           
            s_y.append(beta[i] - c * y[i])
            
        pi_c = {'c': c, 's_x': s_x, 's_y': s_y}    
            
        return mpk, msk, pi_c
        
    def UKeyGen(self, pp, mpk, pi_c):
        # The signer verifies the NIZKP pi_c
        verify = 0        
        concatenate_Y = ''
        concatenate_Y_prime = ''
        for i in range(pp['L']):
            concatenate_Y += str(mpk['Y'][i])
            concatenate_Y_prime += str(mpk['Y'][i] ** pi_c['c'] * pp['g2'] ** pi_c['s_y'][i])
        
        if pi_c['c'] == self.group.hash(str(mpk['X']) + str(mpk['X'] ** pi_c['c'] * pp['g2'] ** pi_c['s_x']) + concatenate_Y + concatenate_Y_prime, ZR):
            verify += 1
            #print('The NIZKP pi_c is correct!')          
        else: 
            verify += 0
            #print('The NIZKP pi_c is wrong!')       
                                                        
        #Set usk and attr as empty arrays
        usk, attr = [], []
        
        # choose a generator and a message
        g1, m0 = self.group.random(G1), self.group.random(ZR)
        
        # Choose the value of s_u, usk, and attr
        for i in range(pp['L']):
            s_u = self.group.random(ZR)
            usk.append(s_u)
            attr.append(g1 ** s_u)         
        
        # Set the value of upk, did, and vc. Note that the credentials are omitted in vc.
        did = upk = attr[0] 
        vc = attr     
        
        # Create a NIZKP     
        d, P, f = [], [], []    
        for i in range(pp['L']):
            k = self.group.random(ZR)
            d.append(k)
            P.append(g1 ** k)
                    
        c = self.group.hash(str(g1) + str(attr) + str(P) + str(m0), ZR)   
            
        for i in range(pp['L']):
            f.append(d[i] - c * usk[i])

        pi0 = {'g1': g1, 'm0': m0, 'c': c, 'f': f}          
        
        return usk, did, vc, pi0

    def randCre(self, pp, msk, did, vc, pi0):
        g1 = pi0['g1']
    
        # Verify the ZKP result    
        P_prime = []
        for i in range(pp['L']):
            P_prime.append(g1 ** pi0['f'][i] * vc[i] ** pi0['c'])
            
        verify = 0
        if pi0['c'] == self.group.hash(str(g1) + str(vc) + str(P_prime) + str(pi0['m0']), ZR):
            verify += 1
            #print('The NIZKP pi0 is correct!')          
        else: 
            verify += 0
            #print('The NIZKP pi0 is wrong!')
        
        # Randomise the credentials
        a = self.group.random(ZR)
        sigma1 = h1 = g1 ** a
            
        prod = 1
        for i in range(pp['L']): 
            prod *= vc[i] ** (a * msk['y'][i])
        
        sigma2 = sigma1 ** msk['x'] * prod
        
        rcre = {'sigma1': sigma1, 'sigma2': sigma2}
        
        return rcre
            
    def anonPre(self, pp, mpk, usk, rcre, msg):  
        verify = 0      
        
        prod = 1
        for i in range(pp['L']):
            prod *= mpk['Y'][i] ** usk[i]
        
        # Verify the credential sigma1 and sigma2
        if pair(rcre['sigma1'], mpk['X'] * prod) == pair(rcre['sigma2'], pp['g2']):    
            verify += 1
            #print('The credentail is correct!')          
        else: 
            verify += 0
            #print('The credential is wrong!')    
                     
        r1, r2 = self.group.random(ZR), self.group.random(ZR)
        
        sigma1_prime = rcre['sigma1'] ** r1
        sigma2_prime = (rcre['sigma2'] * rcre['sigma1'] ** r2) ** r1                    
        sigma3_prime = pp['g2'] ** r2 * prod
                                                            
        # Create a new NIZKP
        alpha = self.group.random(ZR)
        
        lamb = []
        for i in range(pp['L']):        
            lamb.append(self.group.random(ZR))
                    
        #print(lamb)            
        Y2 = 1
        for i in range(pp['L']):  
            Y2 *= mpk['Y'][i] ** lamb[i]
        
        C_sigma3 = pp['g2'] ** alpha * Y2 
                     
        c = self.group.hash(str(pp) + str(sigma3_prime) + str(C_sigma3) + str(msg), ZR)  
                              
        f0 = alpha - c * r2                                             
        f = []
        for i in range(pp['L']):  
            f.append(lamb[i] - c * usk[i])    
           
        pi1 = {'c': c, 'f0': f0, 'f': f}
        
        sigma = {'sigma1_prime': sigma1_prime, 'sigma2_prime': sigma2_prime, 'sigma3_prime': sigma3_prime, 'pi1': pi1}
        return sigma
        
    def aVerify(self, pp, mpk, sigma, msg):
        # Check every verification step 
        
        verify = 0
        if sigma['sigma1_prime'] != 1 and sigma['sigma2_prime'] != 1:
            #print('1 is correct!')    
            verify += 1             
        else:
            #print('1 is wrong')    
            verify += 0  
                                        
        if pair(sigma['sigma2_prime'], pp['g2']) == pair(sigma['sigma1_prime'], mpk['X'] * sigma['sigma3_prime']):
            #print('2 is correct!')    
            verify += 1
        else:
            #print('2 is wrong!')          
            verify += 0
                                    
        Y = 1
        for i in range(pp['L']):
            Y *= mpk['Y'][i] ** sigma['pi1']['f'][i] 
 
        C_sigma3_prime = (pp['g2'] ** sigma['pi1']['f0']) * Y * (sigma['sigma3_prime'] ** sigma['pi1']['c']) 
                                        
        c = self.group.hash(str(pp) + str(sigma['sigma3_prime']) + str(C_sigma3_prime) + str(msg), ZR)        
                                                                 
        if sigma['pi1']['c'] != c:
            #print('3 is wrong!')           
            verify += 0                   
        else: 
            #print('3 is correct!')        
            verify += 1
        
        if verify == 3:
            return 1
        else: 
            return 0
        

        
        
        
        
        
        
        
            
            
            
            
            
            
              
