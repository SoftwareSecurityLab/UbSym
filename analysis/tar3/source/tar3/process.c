/**********************************************************

		Utilities for processing treatments

			- Append
			- Sort
			- Trim

**********************************************************/

#include "defns.h"
#include "types.h"
#include "global.h"

#define	Inc 1024

/*******************************************************************
		Check if one treatment belongs to a treatment set
*******************************************************************/

Boolean Belong(TreatItem OneItem, TreatItem *Items, int MaxItems)
/*--------------*/
{
	int i,j,k,Num,Found;
	Boolean Same=false;

	Num = OneItem._num;
	ForEach(i, 0, MaxItems)
	{
		Found=-1;
		if ( Items[i]._num == Num )
		{
			ForEach(j, 0, Num)
			{
				ForEach(k, 0, Num)
				{
					if ( OneItem._candiSet[j]._att == Items[i]._candiSet[k]._att && 
						 OneItem._candiSet[j]._val == Items[i]._candiSet[k]._val )
						 Found++;
				}
			}
			if ( Found == Num )
			{
				Same = true;
				break;
			}
		}
	}
	return Same;
}

/**************************************************************
		Append one treatment to treatments  
**************************************************************/
     
void AppendTreat(TreatItem OneItem,TreatItem* Items,int *MaxItems, int *MaxSpace)
{
	int i, Index;

	
	if ( ++(*MaxItems) >= (*MaxSpace) )
	{
		(*MaxSpace) += Inc;
		Items = (TreatItem *)realloc(Items, (*MaxSpace)*sizeof(TreatItem));
	}

	Index = (*MaxItems);
	Items[Index]._num = OneItem._num;
	Items[Index]._worth_data = OneItem._worth_data;
	Items[Index]._worth_test = OneItem._worth_test;

	Items[Index]._candiSet = (CandiItem *) calloc(MaxTreatSize,sizeof(CandiItem));
	if ( OneItem._num+1 > MaxTreatSize ) printf("error! AppendTreat()\n");
	ForEach(i, 0, OneItem._num)
	{
		Items[Index]._candiSet[i]._att = OneItem._candiSet[i]._att;
		Items[Index]._candiSet[i]._val = OneItem._candiSet[i]._val;
	}
}

/**************************************************************
		treatment assignment
**************************************************************/

TreatItem AssignTreat(TreatItem Data)
{
	TreatItem Target;
	int i,Num;

	Num = Data._num;
	Target._num = Data._num;
	Target._worth_data = Data._worth_data;
	Target._worth_test = Data._worth_test;

	Target._candiSet = (CandiItem *) calloc(MaxTreatSize,sizeof(CandiItem));
	if ( Num+1 > MaxTreatSize ) printf("error! AssignTreat()\n");
	ForEach(i, 0, Num)
	{
		Target._candiSet[i]._att = Data._candiSet[i]._att;
		Target._candiSet[i]._val = Data._candiSet[i]._val;
	}
	return Target;
}


/**************************************************************
		Sort treatments 
**************************************************************/
void SortTreat(TreatItem *Items, int MaxItems, char Dir)
{
	int i,j;
	Boolean swap;
	float worth1, worth2;
	TreatItem TmpItem;

	TmpItem._candiSet = (CandiItem *) calloc(MaxTreatSize,sizeof(CandiItem));
	ForEach(i, 0, MaxItems-1)
	{
		ForEach(j, i+1, MaxItems)
		{
			swap = false;
			worth1 = Items[i]._worth_data;
			worth2 = Items[j]._worth_data;
			if ( Dir == 'A' )
			{
				if ( worth1 > worth2 )	swap = true;
			}
			else if ( Dir == 'D' )
			{
				if ( worth1 < worth2 )	swap = true;
			}
			if ( swap ) 
			{
				TmpItem = AssignTreat(Items[i]);
				Items[i] = AssignTreat(Items[j]);
				Items[j] = AssignTreat(TmpItem);
			}
		}
	}
}

/**************************************************************
		Trim treatments  
	- Assume treatments are sorted(descendantly)
	- Append those been truncated to faild set
	- Return the minimum worth 
**************************************************************/

float TrimTreat(TreatItem *Items, int *MaxItems, int MaxAllowed)
{
	int i, Index;
	float worth;

	Index = *MaxItems;
	
	/*if total treatments<MaxAllowed, minimum worth=1 */

	if ( Index <= MaxAllowed-1 )
	{
		worth = 1;		
		return worth;
	}

	ForEach(i, MaxAllowed, Index)
	{
		if ( MaxFailedRx+1 >= FailedRxSpace )
		{
			FailedRxSpace += Inc;
			FailedRx = (TreatItem *)realloc(FailedRx, FailedRxSpace*sizeof(TreatItem));
		}
		AppendTreat(Items[i], FailedRx, &MaxFailedRx, &FailedRxSpace);
	}

	Index = MaxAllowed -1;
	(*MaxItems) = Index;
	worth = Items[Index]._worth_data;
	
	return worth;
}