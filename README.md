# UbSym
UbSym attempts to improve the efficiency of symbolic execution technique and use it to detect a group of memory corruption vulnerabilities in binary programs. Instead of applying symbolic execution to the whole program, this tool initially determines a program test unit, probably containing vulnerability, using static analysis and based on the defined specifications for memory corruption vulnerabilities. Then the constraint tree of the program unit is extracted using symbolic execution so that every node in this constraint tree contains the desired path and vulnerability constraints. Finally, using the curve fitting technique and treatment learning the system inputs are estimated consistent with these constraints. Thus, new inputs are generated that reach the vulnerable instructions in the desired unit from the beginning of the program and cause vulnerability aactivation in those instructions.

Analysis Steps of UbSym
------------
* Static Analysis on x64 Binary Codes for Finding Possibly Vulnerable Units
* Symbolic Execution on Test Units
* Monte Carlo Simulation and Curve Fitting
* Detecting Vulnerability and Generating Appropriate Inputs for Activating of the Vulnerability

## Supported Vulnerabilities
- [x] Heap-Based Buffer Overflow
- [x] Stack-Based Buffer Overflow
- [x] Double-Free
- [x] Use-After-Free

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
### Step 2: Cloning Files to Use UbSym
```
git clone https://github.com/SoftwareSecurityLab/UbSym
```
### Step 3: Installing Requirements
Now install project requirements using `requirements.txt` file:
```
pip install -r requirements.txt
```
Running Test Cases
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
### Testing UbSym
You can see possibly vulnerable units contaning double-free vulnerability in a binary program:
```
chmod +x run.py; ./run.py -b program -t DF
```
For example, you want to analyze the function "CWE415_Double_Free__malloc_free_int_01_bad" as a vulnerable unit:<br />
We need one argument with the maximum length of 100 bytes as the input "argv", making the possible vulnerability active in the "CWE415_Double_Free__malloc_free_int_01_bad" unit, so we use `-s 100` for the sizes option and `-a 1` for the args option.
```
./run.py -b program -t DF -p 'void CWE415_Double_Free__malloc_free_int_01_bad(char*)' -s 100 -a 1
```
### Results
Compile programs using [`executable.sh`](https://github.com/SoftwareSecurityLab/UbSym/blob/main/tests/executable.sh) script and run [`benchmarks_running.py`](https://github.com/SoftwareSecurityLab/UbSym/blob/main/benchmarks_running.py) file to analyze all programs of tests directory.
```
chmod +x ./tests/executable.sh; ./tests/executable.sh
chmod +x benchmarks_running.py; ./benchmarks_running.py
```
We wish you happy testing!😄

Known Issues
------------
You may get the message "node i is not satisfiable" since the detection tool can not generate appropriate input data if the symbolic buffer does not have enough space to hold the generated input. In this situation, you have to increase the value of parameters `BUF_SYMBOLIC_BYTES` and `MAX_STR_LEN` in the [`VTree.py`](https://github.com/SoftwareSecurityLab/UbSym/blob/main/analysis/VTree.py) file.

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
    <img src="https://raw.githubusercontent.com/SaraBaradaran/Heap-Overflow-Detection/main/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_01_bad.png" alt="CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_01_bad" width="1100">
  </a>
</div>
