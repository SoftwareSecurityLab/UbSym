# UbSym
UbSym attempts to improve the efficiency of symbolic execution technique and use it to detect a group of memory corruption vulnerabilities in binary programs. Instead of applying symbolic execution to the whole program, this tool initially determines a program test unit, probably containing vulnerability, using static analysis and based on the defined specifications for memory corruption vulnerabilities. Then the constraint tree of the program unit is extracted using symbolic execution so that every node in this constraint tree contains the desired path and vulnerability constraints. Finally, using the curve fitting technique and treatment learning the system inputs are estimated consistent with these constraints. Thus, new inputs are generated that reach the vulnerable instructions in the desired unit from the beginning of the program and cause vulnerability aactivation in those instructions.

Analysis Steps of UbSym
------------
* Static Analysis on x64 Binary Codes for Finding Possibly Vulnerable Units
* Symbolic Execution on Test Units
* Monte Carlo Simulation and Curve Fitting
* Detecting Vulnerability and Generating Appropriate Inputs for Activating of the Vulnerability

## Requirements
- Python3
- angr Framework ([Installation](https://angr.io))

Getting Started
------------
### Step 1: Creating Virtual Environment
Create and activate a virtual environment:
```
sudo apt-get install virtualenv
virtualenv -p /usr/bin/python3 env
source env/bin/activate
```
### Step 2: Cloning Files to Use Heap Overflow Detection Tool
```
git clone https://github.com/SoftwareSecurityLab/UbSym
```
### Step 3: Installing Requirements
Now install project requirements using `requirements.txt` file:
```
pip install -r requirements.txt
```
Running The Tests
------------
Everything is completed. Now you can test your desired code using our tool. We put some test cases from the [NIST SARD](https://samate.nist.gov/SRD/) benchmark vulnerable programs in this repository by which you can test our vulnerability detection tool.
### Options
```
-h or --help        HELP
-b or --binary      BINARY     [The Name of Binary File You Want to Analyze]
-p or --prototype   PROTOTYPE  [The Prototype of Test Unit You Want to Analyze]
-t or --type        TYPE       [The Type of Vulnerabilities You want to Detect]
-s or --sizes       SIZES      [The Size of Test Unit Arguments]
-a or --args        ARGS       [The Indexes of Argv Passed to The Test Unit As Function Arguments]
-S or --solo        SOLO       [The Solo Mode Avoids Executing Nested Functions in Unit Symbolically]
```
### Testing Executable Code Using Heap Overflow Detection Tool
Not completed yet!

We wish you happy testing!😄

Known Issues
------------
You may get the message "node i is not satisfiable" since the detection tool can not generate appropriate input data if the symbolic buffer does not have enough space to hold the generated input. In this situation, you have to increase the value of parameters in the [`config.py`](https://github.com/SoftwareSecurityLab/Heap-Overflow-Detection/blob/main/Project_Files/source/config.py) file.

## Authors
* **Sara Baradaran** - [SaraBaradaran](https://github.com/SaraBaradaran)
* **Mahdi Heidari** - [mheidari98](https://github.com/mheidari98/)
* **Ali Kamali** - [alikmli](https://github.com/alikmli)
* **Maryam Mouzarani** - [maryam-mouzarani](https://github.com/maryam-mouzarani)

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](https://github.com/SoftwareSecurityLab/Heap-Overflow-Detection/blob/main/LICENSE) file for details

Notes
------------
We have tested our project on Ubuntu 18.04.1 LTS.

<div align="center">
  <a href="https://github.com/SoftwareSecurityLab/Heap-Overflow-Detection">
    <img src="CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_01_bad.png" alt="CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_01_bad" width="1100">
  </a>
</div>

