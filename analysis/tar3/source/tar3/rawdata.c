/**********************************************/
/*								              */
/*	Raw data processing						  */
/*	-------------------						  */
/*									          */
/**********************************************/

#include "defns.h"
#include "types.h"
#include "extern.h"

/************************************************/
/*							                    */
/*  Discretize  continuous attributes			*/
/*												*/
/************************************************/

void  Discretize(DiscreArg)
/*  --------  */
	Boolean DiscreArg;		/*discretization method flag*/
{
	short	Att;
	void	DiscreAtt();
	void	PrintDiscre();		

	ForEach(Att, 0, MaxAtt)
    {
		/*  discretize only continuous values */

		if ( ! MaxAttVal[Att] )			/* MaxAttVal[Att] == 0 */
		{
			if ( !strcmp(AttValName[Att][0],"continuous") )
			{
				DiscreAtt(Att,DiscreArg);
				/* print out results --- for debugg purpose only */
				/*PrintDiscre(Att);*/
			}
		}
	}
}

/************************************************/
/*							                    */
/*  Print out Discretization results			*/
/*	(for debug purpose only)					*/
/*												*/
/************************************************/
void PrintDiscre(Att)
/*  --------  */
    short	Att;
{
	int i;

	printf("\n%s: ",AttName[Att]);
	ForEach(i, 0, MaxAttVal[Att])
	{
		printf("%s ",AttValName[Att][i]);
	}
}

/************************************************************************/
/*									                                    */
/*  Discretize a single continuous attribute							*/
/*	-- Sort the different values										*/
/*	-- Divided into percentile bands according to the granularity		*/
/*  On completion, relace the attribute value with its band				*/
/*																		*/
/************************************************************************/

#define Inc 100

void  DiscreAtt(Att,DiscreArg)
/*  --------  */
    short	Att;
	Boolean	DiscreArg;			/*discretization method flag*/
{
	int		Band;
	long	i,j,k, ValNo, MaxDiffVal ,BandNo,ValCeiling=Inc;
	Boolean	Same,Find;
	float	*SortVal,Cv,Min,Max;
	char	buffer[200];

	String	CopyString();
	void	quickSort();

	/*Get (different) values for a given attribute -- SortVal[0..ValNo]*/
	
	ValNo=-1;
	SortVal = (float *) calloc((MaxItem+1), sizeof(float));

	ForEach(i, 0, MaxItem)
	{
		Cv=CVal(Item[i],Att);
		if ( Cv==Unknown )	continue;	/* skip unknown value */

		if ( DiscreArg )		/* use conventional percentage chop(default)*/
		{
			SortVal[++ValNo]=Cv ;
		}
		else
		{
			Same=false;				/* percentage chop on different values */
			ForEach(j, 0, ValNo)
			{
				if (Cv == SortVal[j]) 
				{
					Same=true;
					break;
				}
			}
			if (! Same)	SortVal[++ValNo]=Cv ;
		}
	}

	/*Sort values */
	quickSort(SortVal,0,ValNo);

	/* find out how many different values */
	if ( DiscreArg )		
	{
		MaxDiffVal = 0;
		ForEach(i, 1, ValNo)
		{
			if (SortVal[i] != SortVal[i-1])
			{
				MaxDiffVal++;				
			}
		}
	}
	else
	{
		MaxDiffVal = ValNo;
	}

	/* Record the band info */

	Band=Granularity-1;			/* max band for an attribute */
	if ( MaxDiffVal < Granularity-1 ) 
	{
		Band=(int)MaxDiffVal;
	}

	BandNo=(ValNo+1)/(Band+1);
	if ( (BandNo+1)*(Band+1) < ValNo+1 )	BandNo++;

	
	MaxAttVal[Att] = Band;
	AttBand[Att]._maxband=Band;

	if ( Band >= ValCeiling )
	{
		ValCeiling += Inc;
		AttValName[Att] = (String *) realloc(AttValName[Att], ValCeiling*sizeof(String));
	}

	AttBand[Att]._min=(float *) calloc(Band+1,sizeof(float));
	AttBand[Att]._max=(float *) calloc(Band+1,sizeof(float));

	k=0;
	ForEach(j,0,Band)
	{
		Min=SortVal[k];
		AttBand[Att]._min[j]=Min;
		
		if (j == Band)
		{
			Max=SortVal[ValNo];					
			AttBand[Att]._max[j]=Max;
			sprintf(buffer,"[%f..%f]",Min,Max);	/* last band=[Min,Max] */
		}
		else
		{
			k += BandNo;			/* k is the first element of the next band */
			Max=SortVal[k];			/* Max= the Min value of next band*/
			while ( Max == Min )
			{
				Max = SortVal[++k];
				BandNo = (ValNo+1-k)/(Band-j);
			}
			AttBand[Att]._max[j]=Max;			
			sprintf(buffer,"[%f..%f)",Min,Max); /* other band=[Min,Max)*/
		}										
		
		AttValName[Att][j] = CopyString(buffer);
	}

	/* Replace the continuous value with its percentile band*/

	/*ForEach(i,0,MaxItem)
	{
		j=0;
		while ( j<= ValNo && (CVal(Item[i], Att) != SortVal[j])) j++;
		DVal(Item[i], Att) = (short) (j/BandNo);
	} */

	ForEach(i,0,MaxItem)
	{
		Cv=CVal(Item[i],Att);

		if ( Cv==Unknown )
		{
			DVal(Item[i], Att) = Unknown;
			continue;
		}

		Find = false;
		ForEach(j,0,AttBand[Att]._maxband)
		{
			Min=AttBand[Att]._min[j];
			Max=AttBand[Att]._max[j];
			if ( j == AttBand[Att]._maxband && Cv >= Min && Cv <= Max ) 
			{
				/* last band: [min..max] */
				Find = true;
				DVal(Item[i], Att) = (short)j;
				break;
			}
			else if ( j != AttBand[Att]._maxband && Cv >= Min && Cv < Max )
			{
				/* other band: [min..max) */
				Find = true;
				DVal(Item[i], Att) = (short)j;
				break;
			}
		}
		if ( !Find )
		{
			printf("\nerror: can't find attribute %s associated band!",AttName[Att]);
			exit(1);
		}
	}
}