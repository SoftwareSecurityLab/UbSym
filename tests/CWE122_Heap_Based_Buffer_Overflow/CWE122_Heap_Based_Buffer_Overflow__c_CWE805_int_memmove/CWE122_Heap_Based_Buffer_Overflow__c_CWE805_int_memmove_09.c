/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_09.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.label.xml
Template File: sources-sink-09.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sink: memmove
 *    BadSink : Copy int array to data using memmove
 * Flow Variant: 09 Control flow: if(GLOBAL_CONST_TRUE) and if(GLOBAL_CONST_FALSE)
 *
 * */

#include "std_testcase.h"

struct fp 
{
    void (*fptr)(const char*);
};

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_09_bad(char * activator)
{
    int * data;
    struct fp * ptr;
    data = NULL;
    ptr = NULL;
    if(GLOBAL_CONST_TRUE)
    {
        /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
        data = (int *)malloc(5*sizeof(int));
        if (data == NULL) {exit(-1);}
        ptr = (struct fp *)malloc(sizeof(struct fp));
        if (ptr == NULL) {exit(-1);}
    }
    {
        int source[100] = {0}; /* fill with 0's */
        ptr->fptr = printLine;
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        if (activator[0] == '7' && activator[1] == '/' && activator[2] == '4'
    	&& activator[3] == '2' && activator[4] == 'a' && activator[5] == '8' && activator[75] == 'a') 
        {
            memmove(data, source, 100*sizeof(int));
        }
        ptr->fptr("That's OK!"); 
        printIntLine(data[0]);
        free(data);
        free(ptr);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B1() - use goodsource and badsink by changing the GLOBAL_CONST_TRUE to GLOBAL_CONST_FALSE */
static void goodG2B1()
{
    int * data;
    struct fp * ptr;
    data = NULL;
    ptr = NULL;
    if(GLOBAL_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
        data = (int *)malloc(100*sizeof(int));
        if (data == NULL) {exit(-1);}
        ptr = (struct fp *)malloc(sizeof(struct fp));
        if (ptr == NULL) {exit(-1);}
    }
    {
        int source[100] = {0}; /* fill with 0's */
        ptr->fptr = printLine;
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memmove(data, source, 100*sizeof(int));
        ptr->fptr("That's OK!"); 
        printIntLine(data[0]);
        free(data);
        free(ptr);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if statement */
static void goodG2B2()
{
    int * data;
    struct fp * ptr;
    data = NULL;
    ptr = NULL;
    if(GLOBAL_CONST_TRUE)
    {
        /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
        data = (int *)malloc(100*sizeof(int));
        if (data == NULL) {exit(-1);}
        ptr = (struct fp *)malloc(sizeof(struct fp));
        if (ptr == NULL) {exit(-1);}
    }
    {
        int source[100] = {0}; /* fill with 0's */
        ptr->fptr = printLine;
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memmove(data, source, 100*sizeof(int));
        ptr->fptr("That's OK!"); 
        printIntLine(data[0]);
        free(data);
        free(ptr);
    }
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_09_good()
{
    goodG2B1();
    goodG2B2();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */


int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_09_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_09_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


