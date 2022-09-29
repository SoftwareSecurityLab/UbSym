/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67a.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_dest.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: cat
 *    BadSink : Copy string to data using strcat
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

struct fp 
{
    void (*fptr)(const char*);
};

typedef struct _CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType
{
    char * structFirst;
} CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b_badSink(CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType myStruct, char * activator);

void CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_bad(char * activator)
{
    char * data;
    struct fp * ptr;
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType myStruct;
    data = NULL;
    ptr = NULL;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (char *)malloc(20*sizeof(char));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    ptr->fptr = printLine;
    myStruct.structFirst = data;
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b_badSink(myStruct, activator);
    ptr->fptr("That's OK!"); 
    free(ptr);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b_goodG2BSink(CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType myStruct);

static void goodG2B()
{
    char * data;
    struct fp * ptr;
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType myStruct;
    data = NULL;
    ptr = NULL;
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    ptr->fptr = printLine;
    myStruct.structFirst = data;
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b_goodG2BSink(myStruct);
    ptr->fptr("That's OK!"); 
    free(ptr);
}

void CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_good()
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
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


