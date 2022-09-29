/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_21.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-21.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sink: memmove
 *    BadSink : Copy string to data using memmove
 * Flow Variant: 21 Control flow: Flow controlled by value of a static global variable. All functions contained in one file.
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

struct fp 
{
    void (*fptr)(const char*);
};

#ifndef OMITBAD

/* The static variable below is used to drive control flow in the source function */
static int badStatic = 0;

static char * badSource(char * data)
{
    if(badStatic)
    {
        /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
        data = (char *)malloc(20*sizeof(char));
        if (data == NULL) {exit(-1);}
        data[0] = '\0'; /* null terminate */
    }
    return data;
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_21_bad(char * activator)
{
    char * data;
    struct fp * ptr;
    data = NULL;
    ptr = NULL;
    badStatic = 1; /* true */
    data = badSource(data);
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    {
        ptr->fptr = printLine;
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        if (activator[0] == '7' && activator[1] == '/' && activator[2] == '4'
        && activator[3] == '2' && activator[4] == 'a' && activator[5] == '8' && activator[75] == 'a') 
        {
	    memmove(data, activator, strlen(activator)*sizeof(char));
        }
        ptr->fptr("That's OK!");    
        free(data);
        free(ptr);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The static variables below are used to drive control flow in the source functions. */
static int goodG2B1Static = 0;
static int goodG2B2Static = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
static char * goodG2B1Source(char * data)
{
    if(goodG2B1Static)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        data[0] = '\0'; /* null terminate */
    }
    return data;
}

static void goodG2B1(char * source)
{
    char * data;
    struct fp * ptr;
    data = NULL;
    ptr = NULL;
    goodG2B1Static = 0; /* false */
    data = goodG2B1Source(data);
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    {
        ptr->fptr = printLine;
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        memmove(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        ptr->fptr("That's OK!");    
        free(data);
        free(ptr);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
static char * goodG2B2Source(char * data)
{
    if(goodG2B2Static)
    {
        /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        data[0] = '\0'; /* null terminate */
    }
    return data;
}

static void goodG2B2(char * source)
{
    char * data;
    struct fp * ptr;
    data = NULL;
    ptr = NULL;
    goodG2B2Static = 1; /* true */
    data = goodG2B2Source(data);
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    {
        ptr->fptr = printLine;
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        memmove(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        ptr->fptr("That's OK!");    
        free(data);
        free(ptr);
    }
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_21_good(char * source)
{
    goodG2B1(source);
    goodG2B2(source);
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
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_21_good(argv[1]);
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_21_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


