# EvasiveProcessHollowing
Evasive Process Hollowing PoC

Proof of concept code which demonstrate a few of the "evasive process hollowing" techniques analyzed in the white paper "What Malware Authors Don't want you to know - Evasive Hollow Process Injection" written by Monnappa K A.  The PoC code can be used as a testbed to replicate the memory forensics findings discussed in the white paper.

* The resource file "HollowProcessInjection.rc" has a hardcodeed path to the executable that is to be injected.  The RCDATA path must be changed to reflect the .exe location on the host machine.  
#### 1. Process Hollowing - Allocation in a different address and PEB modification w/ process hollowing
Poc: [HollowProcessInjection1](https://github.com/reevesrs24/EvasiveProcessHollowing/tree/master/HollowProcessInjection1)

#### 2. Process Hollowing - Allocation in a different address and PEB modification w/o process hollowing
Poc: [HollowProcessInjection2](https://github.com/reevesrs24/EvasiveProcessHollowing/tree/master/HollowProcessInjection2)

#### 3. Process Hollowing - Address of Entry point Modification w/ changing the Memory Protection to PAGE_EXECUTE_WRITECOPY
Poc: [HollowProcessInjection3](https://github.com/reevesrs24/EvasiveProcessHollowing/tree/master/HollowProcessInjection3)


#### Sources:
[What Malware Authors Don't want you to know - Monnappa K A](https://www.blackhat.com/docs/asia-17/materials/asia-17-KA-What-Malware-Authors-Don't-Want-You-To-Know-Evasive-Hollow-Process-Injection-wp.pdf)\
[Process Hollowing - John Leitch](https://www.autosectools.com/process-hollowing.pdf)
