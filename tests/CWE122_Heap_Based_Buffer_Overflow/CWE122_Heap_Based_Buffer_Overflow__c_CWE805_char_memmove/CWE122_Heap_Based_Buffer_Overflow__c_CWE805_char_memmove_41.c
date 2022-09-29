/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-41.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sink: memmove
 *    BadSink : Copy string to data using memmove
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

struct fp 
{
    void (*fptr)(const char*);
};

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41_badSink(char * data, char * activator)
{
    { 
	/* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
	if (activator[0] == '7' && activator[1] == '/' && activator[2] == '4'
	&& activator[3] == '2' && activator[4] == 'a' && activator[5] == '8' && activator[75] == 'a') 
	{
	    memmove(data, activator, strlen(activator)*sizeof(char));
	}
	free(data);
    }
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41_bad(char * activator)
{
    char * data;
    struct fp * ptr;
    data = NULL;
    ptr = NULL;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (char *)malloc(20*sizeof(char));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    data[0] = '\0'; /* null terminate */
    ptr->fptr = printLine;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41_badSink(data, activator);
    ptr->fptr("That's OK!"); 
    free(ptr);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41_goodG2BSink(char * data, char * source)
{
    {
	/* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
	memmove(data, source, 100*sizeof(char));
	data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
	free(data);
    }
}

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B(char * source)
{
    char * data;
    struct fp * ptr;
    data = NULL;
    ptr = NULL;
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    data[0] = '\0'; /* null terminate */
    ptr->fptr = printLine;
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41_goodG2BSink(data, source);
    ptr->fptr("That's OK!"); 
    free(ptr);
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41_good(char * source)
{
    goodG2B(source);
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
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41_good(argv[1]);
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memmove_41_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


