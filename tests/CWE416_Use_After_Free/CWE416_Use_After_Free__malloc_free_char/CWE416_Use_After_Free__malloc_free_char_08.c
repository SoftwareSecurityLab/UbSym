/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_char_08.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-08.tmpl.c
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 08 Control flow: if(staticReturnsTrue()) and if(staticReturnsFalse())
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* The two function below always return the same value, so a tool
   should be able to identify that calls to the functions will always
   return a fixed value. */
static int staticReturnsTrue()
{
    return 1;
}

static int staticReturnsFalse()
{
    return 0;
}

#ifndef OMITBAD

void CWE416_Use_After_Free__malloc_free_char_08_bad(char * source)
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticReturnsTrue())
    {
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
        free(data);
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        if (source[0] == '7' && source[1] == '/' && source[2] == '4'
	&& source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
        {
	    printLine(data);
	}
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second staticReturnsTrue() to staticReturnsFalse() */
static void goodB2G1()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticReturnsTrue())
    {
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
        free(data);
    }
    if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Don't use data that may have been freed already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticReturnsTrue())
    {
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
        free(data);
    }
    if(staticReturnsTrue())
    {
        /* FIX: Don't use data that may have been freed already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first staticReturnsTrue() to staticReturnsFalse() */
static void goodG2B1()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* FIX: Do not free data in the source */
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        printLine(data);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    char * data;
    /* Initialize data */
    data = NULL;
    if(staticReturnsTrue())
    {
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        memset(data, 'A', 100-1);
        data[100-1] = '\0';
        /* FIX: Do not free data in the source */
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        printLine(data);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    }
}

void CWE416_Use_After_Free__malloc_free_char_08_good()
{
    goodB2G1();
    goodB2G2();
    goodG2B1();
    goodG2B2();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */



int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE416_Use_After_Free__malloc_free_char_08_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE416_Use_After_Free__malloc_free_char_08_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}



