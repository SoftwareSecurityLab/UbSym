/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_03.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-03.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sink: memmove
 *    BadSink : Copy int array to data using memmove
 * Flow Variant: 03 Control flow: if(5==5) and if(5!=5)
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_03_bad(char * source)
{
    int * data;
    int dataBadBuffer[20];
    int dataGoodBuffer[40];
    if(5==5)
    {
        /* FLAW: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
         * buffer in various memory copying functions using a "large" source buffer. */
        data = dataBadBuffer;
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

/* goodG2B1() - use goodsource and badsink by changing the 5==5 to 5!=5 */
static void goodG2B1(char * source)
{
    int * data;
    int dataBadBuffer[50];
    int dataGoodBuffer[100];
    if(5!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataGoodBuffer;
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if data < 40 */
        memmove(data, source, 40*sizeof(int));
        printIntLine(data[0]);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if statement */
static void goodG2B2(char * source)
{
    int * data;
    int dataBadBuffer[50];
    int dataGoodBuffer[100];
    if(5==5)
    {
        /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataGoodBuffer;
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if data < 40 */
        memmove(data, source, 40*sizeof(int));
        printIntLine(data[0]);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_03_good(char * source)
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
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_03_good(argv[1]);
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_03_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


