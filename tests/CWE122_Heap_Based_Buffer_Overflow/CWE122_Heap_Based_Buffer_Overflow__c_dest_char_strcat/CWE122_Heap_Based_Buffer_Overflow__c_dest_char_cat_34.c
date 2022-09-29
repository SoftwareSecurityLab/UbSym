/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_34.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_dest.label.xml
Template File: sources-sink-34.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: cat
 *    BadSink : Copy string to data using strcat
 * Flow Variant: 34 Data flow: use of a union containing two methods of accessing the same data (within the same function)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

struct fp 
{
    void (*fptr)(const char*);
};

typedef union
{
    char * unionFirst;
    char * unionSecond;
} CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_34_unionType;

#ifndef OMITBAD

void CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_34_bad(char * activator)
{
    char * data;
    struct fp * ptr;
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_34_unionType myUnion;
    data = NULL;
    ptr = NULL;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (char *)malloc(20*sizeof(char));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    data[0] = '\0'; /* null terminate */
    myUnion.unionFirst = data;
    {
        char * data = myUnion.unionSecond;
        {
            ptr->fptr = printLine;
            /* POTENTIAL FLAW: Possible buffer overflow if source is larger than sizeof(data)-strlen(data) */
            if (activator[0] == '7' && activator[1] == '/' && activator[2] == '4'
    	    && activator[3] == '2' && activator[4] == 'a' && activator[5] == '8' && activator[75] == 'a') 
            {
                strcat(data, activator);
            }
            ptr->fptr("That's OK!");    
            printLine(data);
            free(data);
            free(ptr);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    char * data;
    struct fp * ptr;
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_34_unionType myUnion;
    data = NULL;
    ptr = NULL;
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    ptr = (struct fp *)malloc(sizeof(struct fp));
    if (ptr == NULL) {exit(-1);}
    data[0] = '\0'; /* null terminate */
    myUnion.unionFirst = data;
    {
        char * data = myUnion.unionSecond;
        {
            char source[100];
            memset(source, 'C', 100-1); /* fill with 'C's */
            source[100-1] = '\0'; /* null terminate */
            ptr->fptr = printLine;
            /* POTENTIAL FLAW: Possible buffer overflow if source is larger than sizeof(data)-strlen(data) */
            strcat(data, source);
            ptr->fptr("That's OK!");    
            printLine(data);
            free(data);
            free(ptr);
        }
    }
}

void CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_34_good()
{
    goodG2B();
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
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_34_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_34_bad(argv[1]);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


