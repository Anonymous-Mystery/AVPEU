'''
:Date:            11/2023
'''
import re, random, sys
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from AnonDID_Updated import AnonDID
from CL_Updated import CL_DAA_A
from BBS_Updated import BBS_DAA_A

def run1(anonDID, L, msg):
    pp = anonDID.Setup(L)
    (mpk, msk, pi_c) = anonDID.CAKeyGen(pp)
    (usk, did, vc, pi0) = anonDID.UKeyGen(pp, mpk, pi_c)
    rcre = anonDID.randCre(pp, msk, did, vc, pi0)
    sigma = anonDID.anonPre(pp, mpk, usk, rcre, msg)
    result = anonDID.aVerify(pp, mpk, sigma, msg)
    
    if result == 0:
        print('Our AnonDID verfication is not passed.')
    if result == 1:
        print('Our AnonDID verfication is successful!')

    with open('Results/Storage overhead (updated).txt', 'a') as f:
        cred_size = sys.getsizeof(str(rcre)) / 1024
        sigma_size = sys.getsizeof(str(sigma)) / 1024
        f.write('Our credential size: ' + str(cred_size) + ' KB')
        f.write('\n')
        f.write('Our signature size: ' + str(sigma_size) + ' KB')
        f.write('\n')           

def run2(CL, L, m):
    pp = CL.Setup(L)
    (mpk, msk, piI) = CL.CAKeyGen(pp)
    (upk, usk, pi) = CL.UKeyGen(pp, mpk, piI)    
    cre = CL.randCre(pp, msk, upk, pi, m)
    sigma = CL.anonPre(pp, cre, mpk, upk, usk, m)
    result = CL.aVerify(pp, mpk, sigma, m)
    
    if result == 0:
        print('The CL-based DAA-A verification is not passed.')
    if result == 1:
        print('The CL-based DAA-A verfication is successful!')
    
    with open('Results/Storage overhead (updated).txt', 'a') as f:
        cred_size = sys.getsizeof(str(cre)) / 1024
        sigma_size = sys.getsizeof(str(sigma)) / 1024
        f.write('CL DAA-A credential size: ' + str(cred_size) + ' KB')
        f.write('\n')
        f.write('CL DAA-A signature size: ' + str(sigma_size) + ' KB')
        f.write('\n')              
        
def run3(CL, L, m):
    pp = CL.Setup(L)
    (mpk, msk, piI) = CL.CAKeyGen(pp)
    (upk, usk, pi) = CL.UKeyGen(pp, mpk, piI)    
    cre = CL.randCre(pp, msk, upk, pi, m)
    sigma = CL.anonPre(pp, cre, mpk, upk, usk, m)
    result = CL.aVerify(pp, mpk, sigma, m)
    
    if result == 0:
        print('The BBS-based DAA-A verification is not passed.')
    if result == 1:
        print('The BBS-based DAA-A verfication is successful!')

    with open('Results/Storage overhead (updated).txt', 'a') as f:
        cred_size = sys.getsizeof(str(cre)) / 1024
        sigma_size = sys.getsizeof(str(sigma)) / 1024
        f.write('BBS DAA-A credential size: ' + str(cred_size) + ' KB')
        f.write('\n')
        f.write('BBS DAA-A signature size: ' + str(sigma_size) + ' KB')
        f.write('\n\n')             

def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('BN254')
    
    # Choose a message to be signed
    msg = pairing_group.random(ZR)
    m = 'abcdefghijklmn'
    
    # Set the maximum number of attributes
    L = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
       
    anonDID = AnonDID(pairing_group)
    CL = CL_DAA_A(pairing_group)  
    BBS = BBS_DAA_A(pairing_group)
    
    for i in L:  
        with open('Results/Storage overhead (updated).txt', 'a') as f:      
            f.write('# L = ' + str(i) + '\n')  
        run1(anonDID, i, msg) 
        run2(CL, i, m)
        run3(BBS, i, m)
           
if __name__ == "__main__":
    debug = True
    main()
