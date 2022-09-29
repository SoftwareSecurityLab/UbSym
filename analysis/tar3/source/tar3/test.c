/************************************************/
/*									            */
/*  Test the treatments on data				    */
/*	--------------------------			        */
/*												*/
/************************************************/

#include "defns.h"
#include "types.h"
#include "extern.h"

int  Score();

/********************************************************/
/*									                    */
/*  Print out distribution for given info				*/
/*									                    */
/*		Y	--	value array for Y axis					*/
/*		X	--	value array for X axis					*/
/*														*/
/********************************************************/

#define MaxLenth	30

void DrawClass(Num,Name,X)
/*  --------  */
	long Num,*X;
	String *Name;
{
	long i,j,Val,Count,MaxVal,ratio,total;

	MaxVal=X[0];
	total = X[0];
	ForEach(i,1,Num)
	{
		Val=X[i];
		total += Val;
		MaxVal=Max(MaxVal,Val);
	}

	printf("\n");
	
	ForEach(i,0,Num)
	{
		ratio = Round(((float)X[i]*100/(float)total));
		printf("\n %15s:", Name[i]);
		Count=MaxLenth * X[i] / MaxVal;
		ForEach(j,0,Count-1)
			printf("~");
		ForEach(j,0,MaxLenth - Count )
			printf(" ");
		printf(" [%6d - %2d%%] ",X[i],ratio);
	}
	printf("\n");
}


/********************************************************/
/*									                    */
/*  Compute the worth of a dataset						*/
/*  When compute the baseline worth, Num = -1			*/
/*									                    */
/*  On completion:										*/ 
/*		--	return that worth							*/
/*		--	print out the class distribution			*/
/*														*/
/********************************************************/

float Worth(TreatItem OneTreatment, Boolean Print)
/*  -----------------------------------  */
{
	float worth=0,Threshold;
	Boolean Yes;
	int	strlen=0;
	long Case,BestOri=0,BestNow=0,ItemNow,*ClassCount;
	int i, TreatSize, Att, Val;
	char msg[2000];

	TreatSize = OneTreatment._num;

	ClassCount = (long *) calloc((MaxClass + 1), sizeof(long));
	ForEach(i,0,MaxClass)
	{
		ClassCount[i]=0;
	}
	
	/* get dataset that satisfies treatmentes */

	ItemNow=-1;
	ForEach(Case, 0, MaxItem)
	{

		if ( Class(Item[Case]) == MaxClass )	BestOri++;

		Yes = true;
		ForEach(i, 0, TreatSize )
		{
			Att = OneTreatment._candiSet[i]._att;
			Val = OneTreatment._candiSet[i]._val;
			if ( DVal(Item[Case], Att) != Val )
			{
				Yes = false;
				break;
			}
		}

		if ( Yes )
		{
			ItemNow++;
			worth += Score( Class(Item[Case]) );
			ClassCount[Class(Item[Case])]++;
			if ( Class(Item[Case]) == MaxClass )	BestNow++;
		}
	}

	if ( ItemNow == -1 )
	{
		worth=0;
		return worth;
	}
	else
		worth =(float) worth / (ItemNow+1) ;


	if ( TreatSize == -1 )	
	{
		Baseline=worth;
		worth = 1;
		strcpy(msg,"No Treatment");
	}
	else
	{
		Threshold = 1;
		if ( Skew )
		{
			if ( BestNow < (float)BestOri * Skew )
				Threshold = (float)BestNow/((float)BestOri*Skew);
		}
		worth = Threshold*worth/Baseline ;

		if (Print)	
		{
			Att = OneTreatment._candiSet[0]._att;
			Val = OneTreatment._candiSet[0]._val;
			strlen = sprintf( msg,"%s=%s",AttName[Att],AttValName[Att][Val]);
			ForEach(i, 1, TreatSize )
			{
				Att = OneTreatment._candiSet[i]._att;
				Val = OneTreatment._candiSet[i]._val;
				strlen += sprintf( msg+strlen,"\n            %s=%s",AttName[Att],AttValName[Att][Val]);
			}
		}
	}

	/* print the class distribution of the dataset */
	if (Print)
	{
		printf("\n Worth=%f",worth);
		printf("\n Treatment:[%s]",msg);
		DrawClass(MaxClass,ClassName,ClassCount);
	}

	free(ClassCount);
    return worth;
}


/********************************************************/
/*									                    */
/*  Test treatments learnt								*/
/*									                    */
/*  On completion:										*/ 
/*	--	print out treatments							*/
/*									                    */
/********************************************************/

void TestTreatment()
/*  ---------------*/
{
	int i;
	float worth;

	if ( MaxTreat < 0 ) return;
	
	ForEach(i, 0, MaxTreat)
	{
		worth=Worth(TreatSet[i],true);
		TreatSet[i]._worth_test=worth;
	}

}


