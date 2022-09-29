/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67b.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-67b.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: memcpy
 *    BadSink : Copy string to data using memcpy
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67_structType
{
    char * structFirst;
} CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67_structType;

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67b_badSink(CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67_structType myStruct, char * activator)
{
    char * data = myStruct.structFirst;
    {
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        if (activator[0] == '7' && activator[1] == '/' && activator[2] == '4'
    	&& activator[3] == '2' && activator[4] == 'a' && activator[5] == '8' && activator[75] == 'a') 
        {
	    memcpy(data, activator, strlen(activator)*sizeof(char));
        }
        free(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67b_goodG2BSink(CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_67_structType myStruct, char * source)
{
    char * data = myStruct.structFirst;
    {
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        memcpy(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        free(data);
    }
}

#endif /* OMITGOOD */
