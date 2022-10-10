/************************************************/
/*									            */
/*  Core procedures for data analyzing		    */
/*	-----------------------------------         */
/*												*/
/************************************************/

#include "defns.h"
#include "types.h"
#include "extern.h"

/************************************************************************/
/*									                                    */
/*  Compute the score for a given class									*/
/*  On completion, return that score									*/
/*																		*/
/************************************************************************/

int  Score(ClassIndex)
/*  --------  */
    short ClassIndex;
{
	int i;
	float score=1;

	/* assume classes are ordered */
	ForEach(i,0,ClassIndex)
		score *= Step;
	
	return (int)score;
}

/********************************************************/
/*									                    */
/*  Print out distribution for given info				*/
/*									                    */
/*		Y	--	value array for Y axis					*/
/*		X	--	value array for X axis					*/
/*														*/
/********************************************************/

#define MaxLenth	30

void Draw(Num,Y,X)
/*  --------  */
	long Num,*Y,*X;
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
		printf("\n %3d:", Y[i]);
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
/*  Compute deltaf distribution							*/
/*									                    */
/*  On completion:										*/ 
/*		--	print out the deltaf distribution			*/
/*		--	get the candidates according to promising	*/
/*														*/
/********************************************************/

void DeltaDist()
/*  --------  */
{
	short	Att;
	float	temp, *deltaf;
	int		Band,MaxBand;
	long	Case,*FClass,FAll,i,tmpInt;
	int		*fVal,*fCount,fNo,index,fDiff;

	int		Which();
	void	quickSort();
	
	MaxBand=Max(Granularity,10);
	FClass = (long int *) calloc((MaxClass + 1), sizeof(int));
	deltaf = (float *) calloc((MaxAtt+1)*(MaxBand), sizeof(float));
	DistSet= (DistItem *) calloc((MaxAtt+1)*(MaxBand),sizeof(DistItem));
	MaxDistSet=-1;

	/* compute the deltaf of each attribute band */
	fNo=-1;
	ForEach(Att, 0, MaxAtt)
	{
		/* only compute those satisfy CHANGES */

		if ( !strcmp(AttValChg[Att][0],"ignore") )
			continue;

		ForEach(Band, 0, MaxAttVal[Att])
		{
			if ( strcmp(AttValChg[Att][0],"true") )
			{
				index = Which(AttValName[Att][Band], AttValChg[Att], 0, MaxAttChg[Att]);
				if ( index < 0 )	continue;
			}

			if (MaxAttVal[Att]+1 > MaxBand)
			{
				MaxBand= (MaxAttVal[Att]+1)+10;
				deltaf = (float *) realloc(deltaf,(MaxAtt+1)*(MaxBand)*sizeof(float));
				DistSet= (DistItem *) realloc(DistSet,(MaxAtt+1)*(MaxBand)*sizeof(DistItem));
			}

			/* initialize counter */

			ForEach(i,0,MaxClass)
			{
				FClass[i]=0;
				FAll=0;
			}

			ForEach(Case, 0, MaxItem)
			{
				if ( DVal(Item[Case],Att) == Band)
				{
					FClass[Class(Item[Case])]++;
					FAll++;
				}
			}

			temp=0;
			ForEach(i,0,MaxClass-1)
			{
				temp += (Score(MaxClass)-Score(i)) * (FClass[MaxClass] - FClass[i]);
			}
			
			deltaf[++fNo]=(float)Round(temp/FAll); 

			/* record deltaf value of each attribute range in DistSet */

			DistSet[++MaxDistSet]._candiItem._att=Att;
			DistSet[MaxDistSet]._candiItem._val=Band;
			DistSet[MaxDistSet]._weight=(int)deltaf[fNo];
			DistSet[MaxDistSet]._flag=true;
			DistSet[MaxDistSet]._CDF=0;

		}
	}

	/* get deltaf distribution */
	
	fVal = (int *) calloc((MaxAtt+1)*(MaxBand), sizeof(int));
	fCount = (int *) calloc((MaxAtt+1)*(MaxBand), sizeof(int));
	fDiff=-1;

	quickSort(deltaf,0,fNo);

	tmpInt=Round(deltaf[0]);
	fVal[++fDiff]=tmpInt;
	fCount[fDiff]=1;

	ForEach(i, 1, fNo)
	{
		if ( Round(deltaf[i])==tmpInt )
		{
			fCount[fDiff]++;
		}
		else
		{
			tmpInt=Round(deltaf[i]);
			fVal[++fDiff]=tmpInt;
			fCount[fDiff]=1;
		}
	}

	printf("\nConfidence1 Distribution:");
	Draw(fDiff,fVal,fCount);
}

/********************************************************/
/*									                    */
/*  Print out detailed distribution info				*/
/*									                    */
/********************************************************/

void SortDistSet();
void OutputDist();

void DistDetail()
/*  --------  */
{
	SortDistSet(DistSet,MaxDistSet);
	OutputDist(DistSet, MaxDistSet);
}
