'''
:Date:            4/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, GT, ZR
from AnonDID_Updated import AnonDID
from CL_Updated import CL_DAA_A
from BBS_Updated import BBS_DAA_A

import re, random, copy
import time


#--------------------------------------------------- Measure average time module ----------------------------------------------
def measure_average_times_AnonDID(anonDID, L, msg, N=5):   
    sum_Setup = 0
    sum_CAKeyGen = 0
    sum_UKeyGen = 0
    sum_randCre = 0
    sum_anonPre = 0
    sum_aVerify = 0

    for i in range(N):
        # setup time
        start_Setup = time.time()
        pp = anonDID.Setup(L)
        end_Setup = time.time()
        time_Setup = end_Setup - start_Setup
        sum_Setup += time_Setup

        # CA key generation time
        start_CAKeyGen = time.time()
        (mpk, msk, pi_c) = anonDID.CAKeyGen(pp)
        end_CAKeyGen = time.time()
        time_CAKeyGen = end_CAKeyGen - start_CAKeyGen 
        sum_CAKeyGen += time_CAKeyGen 

        # User Key generation time
        start_UKeyGen = time.time()
        (usk, did, vc, pi0) = anonDID.UKeyGen(pp, mpk, pi_c)
        end_UKeyGen = time.time()
        time_UKeyGen = end_UKeyGen - start_UKeyGen
        sum_UKeyGen += time_UKeyGen

        # randomisable credential generation time
        start_randCre = time.time()
        rcre = anonDID.randCre(pp, msk, did, vc, pi0)
        end_randCre = time.time()
        time_randCre = end_randCre - start_randCre
        sum_randCre += time_randCre
        
        # Anonymou verifiable presentation time
        start_anonPre = time.time()
        sigma = anonDID.anonPre(pp, mpk, usk, rcre, msg)
        end_anonPre = time.time()
        time_anonPre = end_anonPre - start_anonPre
        sum_anonPre += time_anonPre
        
        # Anonymou verification time
        start_aVerify = time.time()
        result = anonDID.aVerify(pp, mpk, sigma, msg)
        end_aVerify = time.time()
        time_aVerify = end_aVerify - start_aVerify
        sum_aVerify += time_aVerify                       
    
    # compute average time
    time_Setup = sum_Setup/N
    time_CAKeyGen = sum_CAKeyGen/N
    time_UKeyGen = sum_UKeyGen/N
    time_randCre = sum_randCre/N
    time_anonPre = sum_anonPre/N
    time_aVerify = sum_aVerify/N        

    return [time_Setup, time_CAKeyGen, time_UKeyGen, time_randCre, time_anonPre, time_aVerify]

def measure_average_times_DAA_A(DAA, L, m, N=5):   
    sum_Setup = 0
    sum_CAKeyGen = 0
    sum_UKeyGen = 0
    sum_randCre = 0
    sum_anonPre = 0
    sum_aVerify = 0

    for i in range(N):
        # setup time
        start_Setup = time.time()
        pp = DAA.Setup(L)
        end_Setup = time.time()
        time_Setup = end_Setup - start_Setup
        sum_Setup += time_Setup

        # CA key generation time
        start_CAKeyGen = time.time()
        (mpk, msk, piI) = DAA.CAKeyGen(pp)
        end_CAKeyGen = time.time()
        time_CAKeyGen = end_CAKeyGen - start_CAKeyGen 
        sum_CAKeyGen += time_CAKeyGen 

        # User Key generation time
        start_UKeyGen = time.time()
        (upk, usk, pi) = DAA.UKeyGen(pp, mpk, piI)
        end_UKeyGen = time.time()
        time_UKeyGen = end_UKeyGen - start_UKeyGen
        sum_UKeyGen += time_UKeyGen

        # randomisable credential generation time
        start_randCre = time.time()
        cre = DAA.randCre(pp, msk, upk, pi, m)
        end_randCre = time.time()
        time_randCre = end_randCre - start_randCre
        sum_randCre += time_randCre
        
        # Anonymou verifiable presentation time
        start_anonPre = time.time()
        sigma = DAA.anonPre(pp, cre, mpk, upk, usk, m)
        end_anonPre = time.time()
        time_anonPre = end_anonPre - start_anonPre
        sum_anonPre += time_anonPre        
        
        # Anonymou verification time
        start_aVerify = time.time()
        result = DAA.aVerify(pp, mpk, sigma, m)
        end_aVerify = time.time()
        time_aVerify = end_aVerify - start_aVerify
        sum_aVerify += time_aVerify                       
    
    # compute average time
    time_Setup = sum_Setup/N
    time_CAKeyGen = sum_CAKeyGen/N
    time_UKeyGen = sum_UKeyGen/N
    time_randCre = sum_randCre/N
    time_anonPre = sum_anonPre/N
    time_aVerify = sum_aVerify/N        

    return [time_Setup, time_CAKeyGen, time_UKeyGen, time_randCre, time_anonPre, time_aVerify]
           
#-------------------------------------------------- print running time module -------------------------------------------------

def print_running_time(scheme_name, times):
    record = '{:<22}'.format(scheme_name) + format(times[0]*1000, '7.2f') + '   ' + format(times[1]*1000, '7.2f') + '       ' + format(times[2]*1000, '7.2f') + '       ' + format(times[3]*1000, '7.2f') + '      ' + format(times[4]*1000, '7.2f') + '    ' + format(times[5]*1000, '7.2f')
    print(record)
    return record
    

#-------------------------------------------------- run all module ------------------------------------------------------------
def run(pairing_group, L, msg, m):     
    anonDID = AnonDID(pairing_group)
    CL = CL_DAA_A(pairing_group)  
    BBS = BBS_DAA_A(pairing_group) 
        
    anonDID_times = measure_average_times_AnonDID(anonDID, L, msg)     
    CL_times = measure_average_times_DAA_A(CL, L, m)
    BBS_times = measure_average_times_DAA_A(BBS, L, m)
             
    print('\n')
    print('*'*62)
    print('Running times (ms) curve BN254: attribute universe = {} '.format(L))
    print('*'*100)
    algos = ['Setup', 'CAKeyGen', 'UKeyGen', 'RandCre', 'AnonPre', 'AVerify']   
    algo_string = 'Scheme {:<15}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '     ' + algos[3] + '     ' + algos[4] + '     ' + algos[5]
    print('-'*100)
    print(algo_string)
    print('-'*100)
    record1 = print_running_time(anonDID.name, anonDID_times)       
    record2 = print_running_time(CL.name, CL_times)         
    record3 = print_running_time(BBS.name, BBS_times)       
         
    print('-'*100)          
   
    with open('Results/Results (Updated).txt', 'a') as f:
        f.write('*' * 100 + '\n') 
        f.write('Scheme: ' + 'Running times (ms) curve BN254: attribute universe = {} '.format(L) + '\n')
        f.write(algo_string + '\n')
        f.write(record1 + '\n')    
        f.write(record2 + '\n')   
        f.write(record3 + '\n')           
        #f.write('\n')     
    open('Results/Results (Updated).txt', 'r')  
    with open('Results/Results (Updated).txt', 'a') as f:     
        f.write('*' * 100 + '\n')            
    return             

# -------------------------------------------------- Main functions module ---------------------------------------------------    
                  
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('BN254')
    
    # Choose a message to be signed
    msg = pairing_group.random(ZR)    
    m = 'abcdefghijklmn'    
    
    # Set the maximum number of attributes
    attr_universe = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        
    # Run the AnonDID algorithm for all universe sizes  

    for L in attr_universe:  
        run(pairing_group, L, msg, m)    
        
if __name__ == "__main__":
    debug = True
    main()                 
           
