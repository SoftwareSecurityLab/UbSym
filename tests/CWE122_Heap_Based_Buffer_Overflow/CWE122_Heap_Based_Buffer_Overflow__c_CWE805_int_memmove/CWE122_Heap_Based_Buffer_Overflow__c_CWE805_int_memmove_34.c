/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_34.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.label.xml
Template File: sources-sink-34.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: memmove
 *    BadSink : Copy int array to data using memmove
 * Flow Variant: 34 Data flow: use of a union containing two methods of accessing the same data (within the same function)
 *
 * */

#include "std_testcase.h"

struct fp 
{
    void (*fptr)(const char*);
};

typedef union
{
    int * unionFirst;
    int * unionSecond;
} CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_34_unionType;

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_34_bad(char * activator)
{
    int * data;
    struct fp * ptr;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_34_unionType myUnion;
    data = NULL;
    ptr = NULL;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (int *)malloc(5*sizeof(int));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    myUnion.unionFirst = data;
    {
        int * data = myUnion.unionSecond;
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
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    int * data;
    struct fp * ptr;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_34_unionType myUnion;
    data = NULL;
    ptr = NULL;
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (int *)malloc(100*sizeof(int));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    myUnion.unionFirst = data;
    {
        int * data = myUnion.unionSecond;
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
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_34_good()
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
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_34_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memmove_34_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


