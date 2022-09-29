/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.string.label.xml
Template File: sources-sink-67b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sinks: memmove
 *    BadSink : Copy string to data using memmove
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67_structType
{
    char * structFirst;
} CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67_structType;

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67b_badSink(CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67_structType myStruct, char * source)
{
    char * data = myStruct.structFirst;
    {
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
        if (source[0] == '7' && source[1] == '/' && source[2] == '4'
	&& source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
        {
	    memmove(data, source, strlen(source)*sizeof(char));
	}
        printLine(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67b_goodG2BSink(CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_67_structType myStruct, char * source)
{
    char * data = myStruct.structFirst;
    {
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
        memmove(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

#endif /* OMITGOOD */
