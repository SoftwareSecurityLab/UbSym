/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_int64_t_01.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-01.tmpl.c
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE416_Use_After_Free__malloc_free_int64_t_01_bad(char * source)
{
    int64_t * data;
    /* Initialize data */
    data = NULL;
    data = (int64_t *)malloc(100*sizeof(int64_t));
    if (data == NULL) {exit(-1);}
    {
        size_t i=0;
        data[i] = 5LL;
    }
    /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
    free(data);
    /* POTENTIAL FLAW: Use of data that may have been freed */
    if (source[0] == '7' && source[1] == '/' && source[2] == '4'
    && source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
    {
        printLongLongLine(data[0]);
    }
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    int64_t * data;
    /* Initialize data */
    data = NULL;
    data = (int64_t *)malloc(100*sizeof(int64_t));
    if (data == NULL) {exit(-1);}
    {
        size_t i=0;
        data[i] = 5LL;
    }
    /* FIX: Do not free data in the source */
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printLongLongLine(data[0]);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    int64_t * data;
    /* Initialize data */
    data = NULL;
    data = (int64_t *)malloc(100*sizeof(int64_t));
    if (data == NULL) {exit(-1);}
    {
        size_t i=0;
        data[i] = 5LL;
    }
    /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
    free(data);
    /* FIX: Don't use data that may have been freed already */
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    /* do nothing */
    ; /* empty statement needed for some flow variants */
}

void CWE416_Use_After_Free__malloc_free_int64_t_01_good()
{
    goodG2B();
    goodB2G();
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
    CWE416_Use_After_Free__malloc_free_int64_t_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE416_Use_After_Free__malloc_free_int64_t_01_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


