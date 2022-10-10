/**********************************************************

  Generate N Treatments Using Random Sample Algorithm

**********************************************************/

#include "defns.h"
#include "types.h"
#include "global.h"

#define	Inc 1024

double RandomEqualREAL();
int RandomEqualINT();
float Worth();
Boolean Belong();
void AppendTreat();
void SortTreat();
float TrimTreat();

/***************************************************************************
	1. find the least element whose CDF > given CDF 
	2. if elements have the same CDF value, random choose one
	3. when a element is chosen, set flag=false
***************************************************************************/

int Find(double CDF, DistItem* Set, int MaxSet)
{
	int i, Index;
	int MaxFound, *SetFound;
	double CDFound;

	MaxFound = -1;
	SetFound = (int *) calloc((MaxSet+1),sizeof(int));

	/*find the least element whose CDF > given CDF*/
	ForEach(i, 0, MaxSet)
	{
		if ( MaxFound < 0 )
		{
			if ( Set[i]._flag  && Set[i]._CDF >= CDF )	
			{
				SetFound[++MaxFound] = i;
				CDFound = Set[i]._CDF;
			}
		}
		else
		{
			if ( Set[i]._CDF == CDFound )
			{
				if ( Set[i]._flag )
				{
					SetFound[++MaxFound] = i;
				}
			}
			else	
				continue;
		}
	}

	if ( MaxFound == 0 )
	{
		Set[SetFound[0]]._flag = false;
		return SetFound[0];
	}
	else if ( MaxFound > 0 )
	{
		Index = RandomEqualINT(0,MaxFound);
		Set[SetFound[Index]]._flag = false;
		return SetFound[Index];
	}
	else
	{
		/* not possible that can't find a CDF value*/
		printf("\nError: no cdf value found!\n");
		exit(1);
	}
}


/**************************************************************
		Generate a subset of given size 
		Duplicate elements are not allowed
		Tail recursion function
**************************************************************/

void Generate(DistItem* Set, int MaxSet, int SizeGiven, DistItem* Subset, int *MaxSubset)
/*---------------*/
{
	int i,Index;
	double MinCDF,MaxCDF,CDF;
	DistItem AssignFrom();

	/* base case */

	if ( SizeGiven == 0 ) 	return;

	/* find MinCDF and MAXCDF */

	ForEach(i, 0, MaxSet)
	{
		if ( Set[i]._flag )	
		{
			MinCDF = Set[i]._CDF;
			break;
		}
	}
	for(i=MaxSet; i>=0; --i)
	{
		if ( Set[i]._flag )	
		{
			MaxCDF = Set[i]._CDF;
			break;
		}
	}

	/* generate one item */

	CDF = RandomEqualREAL(MinCDF,MaxCDF);
	Index = Find(CDF, Set, MaxSet);
	if ( Index >= 0 )	
		Subset[++(*MaxSubset)] = AssignFrom(Set[Index]);
	
	/*printf("\nSize=%d,CDF=%d,Index=%d",SizeGiven,CDF,Index);*/
	/* generate rest items */

	Generate(Set, MaxSet, SizeGiven-1, Subset, MaxSubset);
}



/********************************************************************
		Validate treatment to treatments
		
		- treatment can't contain same attribute ranges

*******************************************************************/

Boolean Validate(TreatItem OneItem,TreatItem *Items,int MaxItems)
/*------------*/
{
	int i,j,Size;
	Boolean	Same;

	/* check if there are 2 identical attributes */
	Same = false;
	Size = OneItem._num;
	ForEach(i, 0, Size-1)
	{
		ForEach(j, i+1, Size)
		{
			if ( OneItem._candiSet[i]._att == OneItem._candiSet[j]._att )
			{
				Same = true;
				break;
			}
		}
	}
	if ( Same )	return false;

	return true;
}

/**************************************************************
		Process treatments  
		
	- Append current treatments to final set
	- Sort according to worth
	- Trim final set according to maxmum number allowed
	- return the update status
**************************************************************/

Boolean ProcessTreatments(TreatItem* Set,int MaxSet)
{
	int i, Total;

	if ( MaxSet < 0 ) return false;

	/* append */
	Total = MaxTreat+MaxSet+1;
	ForEach( i, 0, MaxSet)
	{
		if ( MaxTreat+1 >= TreatSetSpace )
		{
			TreatSetSpace += Inc;
			TreatSet = (TreatItem *)realloc(TreatSet, TreatSetSpace*sizeof(TreatItem));
		}
		AppendTreat(Set[i], TreatSet, &MaxTreat, &TreatSetSpace);
	}
	if ( MaxTreat != Total ) 
		printf("\nError! ProcessTreatments error!");

	/* sort */
	SortTreat(TreatSet, MaxTreat, 'D');

	/* trim and update the minworth value */
	MinWorth = TrimTreat(TreatSet, &MaxTreat, MaxTreatNum);

	return true;
}

/**************************************************************
		Generate N treatments  
		
	- Each treatment size is randomly given
**************************************************************/

Boolean GetTreatments(int MaxSet, int MinSize, int MaxSize, DistItem* Data, int MaxData)
/*---------------*/
{

	int i,loop, Size, MaxSubset, MaxTreatments, TreatmentsSpace;
	DistItem	*Subset;
	TreatItem	OneTreatment, *Treatments;
	Boolean		Valid;
	float worth;
 
	TreatmentsSpace = Inc;
	Treatments = (TreatItem *) calloc(TreatmentsSpace,sizeof(TreatItem));
	MaxTreatments = -1;
	Subset = (DistItem *) calloc(MaxSize,sizeof(DistItem));

	ForEach(loop, 1, MaxSet)
	{

		/* Reset the flag of distribution data */
		ForEach(i, 0, MaxData)
			Data[i]._flag = true;

		/* generate one treatment of a given size */

		Size = RandomEqualINT(MinSize,MaxSize);    

		MaxSubset = -1;
		Generate(Data,MaxData,Size,Subset,&MaxSubset);	

		/* impossible that can't generate a subset of given size*/
		if ( MaxSubset+1 != Size )
			printf("\nSubset size error! Size-1=%d, MaxSubset=%d",Size-1,MaxSubset);

		OneTreatment._candiSet = (CandiItem *) calloc(MaxSize,sizeof(CandiItem));
		OneTreatment._num = MaxSubset;
		ForEach(i,0,MaxSubset)
		{
			OneTreatment._candiSet[i]._att = Subset[i]._candiItem._att;
			OneTreatment._candiSet[i]._val = Subset[i]._candiItem._val;
		}

		/* validate the current OneTreatment */

		Valid = Validate(OneTreatment,Treatments,MaxTreatments);
		if ( ! Valid )	continue;
		if ( Belong(OneTreatment,Treatments,MaxTreatments) )	continue;
		if ( Belong(OneTreatment,TreatSet,MaxTreat) )	continue;
		if ( Belong(OneTreatment,FailedRx,MaxFailedRx) )	continue;

		worth = Worth(OneTreatment,false);
		OneTreatment._worth_data=worth;
		if ( worth >= MinWorth )
		{
			if ( MaxTreatments+1 >= TreatmentsSpace )
			{
				TreatmentsSpace += Inc;
				Treatments = (TreatItem *)realloc(Treatments, TreatmentsSpace*sizeof(TreatItem));
			}
			AppendTreat(OneTreatment, Treatments, &MaxTreatments, &TreatmentsSpace);
		}
		else
		{
			if ( MaxFailedRx+1 >= FailedRxSpace )
			{
				FailedRxSpace += Inc;
				FailedRx = (TreatItem *)realloc(FailedRx, FailedRxSpace*sizeof(TreatItem));
			}
			AppendTreat(OneTreatment, FailedRx, &MaxFailedRx, &FailedRxSpace);
		}

	}

	/* Process all treatments generated this run */
	return ProcessTreatments(Treatments,MaxTreatments);
}
