/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67a.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__dest.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sinks: cpy
 *    BadSink : Copy string to data using strcpy
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_structType
{
    char * structFirst;
} CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67b_badSink(CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_structType myStruct, char * source);

void CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_bad(char * source)
{
    char * data;
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_structType myStruct;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    /* FLAW: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
     * buffer in various memory copying functions using a "large" source buffer. */
    data = dataBadBuffer;
    data[0] = '\0'; /* null terminate */
    myStruct.structFirst = data;
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67b_badSink(myStruct, source);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67b_goodG2BSink(CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_structType myStruct, char * source);

static void goodG2B(char * source)
{
    char * data;
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_structType myStruct;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
    data = dataGoodBuffer;
    data[0] = '\0'; /* null terminate */
    myStruct.structFirst = data;
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67b_goodG2BSink(myStruct, source);
}

void CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_good(char * source)
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
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_good(argv[1]);
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_67_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


