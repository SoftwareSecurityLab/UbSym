/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67a.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE193.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sinks: cpy
 *    BadSink : Copy string to data using strcpy()
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

struct fp 
{
    void (*fptr)(const char*);
};
/* MAINTENANCE NOTE: The length of this string should equal the 40 */
#define SRC_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

typedef struct _CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_structType
{
    char * structFirst;
} CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67b_badSink(CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_structType myStruct, char * activator);

void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_bad(char * activator)
{
    char * data;
    struct fp * ptr;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_structType myStruct;
    data = NULL;
    ptr = NULL;
    /* FLAW: Did not allocate space based on the source length */
    data = (char *)malloc(20*sizeof(char));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    ptr->fptr = printLine;
    myStruct.structFirst = data;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67b_badSink(myStruct, activator);
    ptr->fptr("That's OK!"); 
    free(ptr);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67b_goodG2BSink(CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_structType myStruct);

static void goodG2B()
{
    char * data;
    struct fp * ptr;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_structType myStruct;
    data = NULL;
    ptr = NULL;
    /* FIX: Allocate space for a null terminator */
    data = (char *)malloc((40+1)*sizeof(char));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    ptr->fptr = printLine;
    myStruct.structFirst = data;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67b_goodG2BSink(myStruct);
    ptr->fptr("That's OK!"); 
    free(ptr);
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_good()
{
    goodG2B();
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
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_cpy_67_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


