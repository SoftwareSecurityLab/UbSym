/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_08.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__dest.label.xml
Template File: sources-sink-08.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sink: cpy
 *    BadSink : Copy string to data using strcpy
 * Flow Variant: 08 Control flow: if(staticReturnsTrue()) and if(staticReturnsFalse())
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* The two function below always return the same value, so a tool
 * should be able to identify that calls to the functions will always
 * return a fixed value.
 */
static int staticReturnsTrue()
{
    return 1;
}

static int staticReturnsFalse()
{
    return 0;
}

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_08_bad(char * source)
{
    char * data;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    if(staticReturnsTrue())
    {
        /* FLAW: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
         * buffer in various memory copying functions using a "large" source buffer. */
        data = dataBadBuffer;
        data[0] = '\0'; /* null terminate */
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
        if (source[0] == '7' && source[1] == '/' && source[2] == '4'
	&& source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
        {
	    strcpy(data, source);
	}
        printLine(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B1() - use goodsource and badsink by changing the staticReturnsTrue() to staticReturnsFalse() */
static void goodG2B1(char * source)
{
    char * data;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataGoodBuffer;
        data[0] = '\0'; /* null terminate */
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
        strncpy(data, source, 100-1);
        printLine(data);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if statement */
static void goodG2B2(char * source)
{
    char * data;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    if(staticReturnsTrue())
    {
        /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataGoodBuffer;
        data[0] = '\0'; /* null terminate */
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
        strncpy(data, source, 100-1);
        printLine(data);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_08_good(char * source)
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
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_08_good(argv[1]);
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_08_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


