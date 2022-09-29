/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_16.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-16.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sink: memmove
 *    BadSink : Copy int array to data using memmove
 * Flow Variant: 16 Control flow: while(1)
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_16_bad(char * source)
{
    int * data;
    int dataBadBuffer[20];
    int dataGoodBuffer[40];
    while(1)
    {
        /* FLAW: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
         * buffer in various memory copying functions using a "large" source buffer. */
        data = dataBadBuffer;
        break;
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if data < strlen(source) */
        if (source[0] == '7' && source[1] == '/' && source[2] == '4'
	&& source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
        {
            memmove(data, source, strlen(source)*sizeof(char));
        }
        printIntLine(data[0]);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() - use goodsource and badsink by changing the conditions on the while statements */
static void goodG2B(char * source)
{
    int * data;
    int dataBadBuffer[20];
    int dataGoodBuffer[40];
    while(1)
    {
        /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataGoodBuffer;
        break;
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if data < 40 */
        memmove(data, source, 40*sizeof(int));
        printIntLine(data[0]);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_16_good(char * source)
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
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_16_good(argv[1]);
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_16_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


