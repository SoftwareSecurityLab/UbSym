/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_dest.label.xml
Template File: sources-sink-67b.tmpl.c
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

typedef struct _CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType
{
    char * structFirst;
} CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType;

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b_badSink(CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType myStruct, char * activator)
{
    char * data = myStruct.structFirst;
    data[0] = '\0'; /* null terminate */
    {
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than sizeof(data)-strlen(data) */
        if (activator[0] == '7' && activator[1] == '/' && activator[2] == '4'
    	&& activator[3] == '2' && activator[4] == 'a' && activator[5] == '8' && activator[75] == 'a') 
        {
            strcat(data, activator);
        }
        printLine(data);
        free(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67b_goodG2BSink(CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_67_structType myStruct)
{
    char * data = myStruct.structFirst;
    data[0] = '\0'; /* null terminate */
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than sizeof(data)-strlen(data) */
        strcat(data, source);
        printLine(data);
        free(data);
    }
}

#endif /* OMITGOOD */
