#include "defns.h"
#include "types.h"
#include "extern.h"

/* quicksort */

typedef float T;				/* type of item to be sorted	*/
typedef long tblIndex;			/* type of subscript			*/

#define compGT(a,b) (a > b)		/* for ascending order			*/

/***********************************
*  insertion sort array a[lb..ub]  *
************************************/
void insertSort(T *a, tblIndex lb, tblIndex ub) 
{
    T t;
    tblIndex i, j;

    for (i = lb + 1; i <= ub; i++) 
	{
        t = a[i];

        /* Shift elements down until insertion point found. */
        for (j = i-1; j >= lb && compGT(a[j], t); j--)
            a[j+1] = a[j];

        /* insert */
        a[j+1] = t;
    }
}

/*******************************
*  partition array a[lb..ub]  *
*******************************/
tblIndex partition(T *a, tblIndex lb, tblIndex ub) 
{
    T t, pivot;
    tblIndex i, j, p;

    /* select pivot and exchange with 1st element */
    p = lb + ((ub - lb)>>1);
    pivot = a[p];
    a[p] = a[lb];

    /* sort lb+1..ub based on pivot */
    i = lb;
    j = ub + 1;
    while (1) 
	{
        while (j > i && compGT(a[--j], pivot));
        while (i < j && compGT(pivot, a[++i])); 
        if (i >= j) break;

        /* swap a[i], a[j] */
        t = a[i];
        a[i] = a[j];
        a[j] = t;
    }

    /* pivot belongs in a[j] */
    a[lb] = a[j];
    a[j] = pivot;

    return j;
}

/******************************
*  quicksort array a[lb..ub]  *
*******************************/
void quickSort(T *a, tblIndex lb, tblIndex ub) 
{
    tblIndex m;

    while (lb < ub) 
	{

        /* quickly sort short lists */
        if (ub - lb <= 12) 
		{
            insertSort(a, lb, ub);
            return;
        }

        /* partition into two segments */
        m = partition (a, lb, ub);

        /* sort the smallest partition    */
        /* to minimize stack requirements */
        if (m - lb <= ub - m) 
		{
            quickSort(a, lb, m - 1);
            lb = m + 1;
        } 
		else 
		{
            quickSort(a, m + 1, ub);
            ub = m - 1;
        }
    }
}

