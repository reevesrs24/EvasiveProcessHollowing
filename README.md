# EvasiveProcessHollowing
Evasive Process Hollowing PoC

Proof of concept code which demonstrate a few of the "evasive process hollowing" techniques analyzed in the white paper "What Malware Authors Don't want you to know - Evasive Hollow Process Injection" written by Monnappa K A.  The PoC code can be used as a testbed to replicate the memory forensics findings discussed in the white paper.

#### 1. Process Hollowing - Allocation in a different address and PEB modification w/ process hollowing
Poc: [HollowProcessInjection1](https://github.com/reevesrs24/EvasiveProcessHollowing/tree/master/HollowProcessInjection1)

#### 2. Process Hollowing - Allocation in a different address and PEB modification w/o process hollowing
Poc: [HollowProcessInjection2](https://github.com/reevesrs24/EvasiveProcessHollowing/tree/master/HollowProcessInjection2)

#### 3. Process Hollowing - Address of Entry point Modification w/ changing the Memory Protection to PAGE_EXECUTE_WRITECOPY
Poc: [HollowProcessInjection3](https://github.com/reevesrs24/EvasiveProcessHollowing/tree/master/HollowProcessInjection3)


