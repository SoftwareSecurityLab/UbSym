/**********************************************************

  Using Random Sample Algorithm to Get Treatments

**********************************************************/

#include "defns.h"
#include "types.h"
#include "global.h"

void Output();
void OutputDist();

/**********************************************************
	Uniform distributed	random number generator

	rand():						[0..RAND_MAX]
	(REAL)rand()/RAND_MAX:		[0..1]
	RandomEqualINT(Low, High)	[Low..High]
	RandomEqualREAL(Low,High)	[Low..High]
 **********************************************************/

void InitializeRandoms()
{
	unsigned int seed;

	seed = (unsigned)time( NULL ); 
/*	seed = 1010817113 ;
	printf("\nrandom seed: %u\n", seed); */
	srand( seed );
}

int RandomEqualINT(int Low, int High)	
{
	return rand() % (High-Low+1) + Low;
}      

double RandomEqualREAL(double Low, double High)
{
	return ((double) rand() / RAND_MAX) * (High-Low) + Low;
}      


/**************************************************************
		Assign DistItem
**************************************************************/

DistItem AssignFrom(DistItem Data)
/*---------------------------------------*/
{
	DistItem Target;

	Target._candiItem._att = Data._candiItem._att;
	Target._candiItem._val = Data._candiItem._val;
	Target._weight = Data._weight;
	Target._CDF = Data._CDF;
	Target._flag = Data._flag;

	return Target;
}


/**************************************************************
		Sort Distribution Dataset According to Weights

		- Sort in ascendent order
**************************************************************/

void SortDistSet(DistItem* Dataset, int MaxNum)
/*---------------------------------------*/
{
	int i,j;
	DistItem TmpItem;

	ForEach(i, 0, MaxNum-1)
	{
		ForEach(j, i+1, MaxNum)
		{
			if ( Dataset[i]._weight > Dataset[j]._weight )
			{
				TmpItem = AssignFrom(Dataset[i]);
				Dataset[i] = AssignFrom(Dataset[j]);
				Dataset[j] = AssignFrom(TmpItem);
			}
		}
	}
}


/**************************************************************
		Compute CDF value for each candidate

  - Assume dataset is sorted
  - Elements with the same weight have the same CDF value.
	
**************************************************************/

void ComputeCDF(DistItem* Dataset, int MaxNum)
/*---------------------------------------*/
{
	long i,Sum, Offset, Weight;
	double MaxCDF;

	/* if distribution has negative numbers, 
	shift up the bottom to 0 */
	Offset = Dataset[0]._weight;
	if ( Offset >= 0 ) 
		Offset = 0;
	else
		Offset = -1*Offset;

	/* compute CDF value */
	Sum = 0;
	ForEach(i,0, MaxNum)
	{
		Weight = Offset + Dataset[i]._weight;
		if ( i == 0 )
			Sum = Weight;
		else
			if ( Dataset[i]._weight  != Dataset[i-1]._weight )
				Sum += Weight;

		Dataset[i]._CDF = (double)Sum;
	}
	MaxCDF = (double)Dataset[MaxNum]._CDF;

	/* normalization */
	ForEach(i,0,MaxNum)
	{
		Dataset[i]._CDF = Dataset[i]._CDF/MaxCDF;
	}

}


/********************************************************/
/*									                    */
/*  Perform N trials to get (stable) treatments			*/
/*									                    */
/*	If no new treatments are generated during a trial   */
/*	stop the procedure						            */
/*									                    */
/********************************************************/

void Simulate()
/*-------------*/
{
	int i,MaxNumThisRun,ActualTrials, CurrentFailed;
	Boolean Improve=true;
	char Msg[200];
	Boolean GetTreatments();

	/* compute CDF value */
	SortDistSet(DistSet,MaxDistSet);
	ComputeCDF(DistSet,MaxDistSet);
	/*OutputDist(DistSet, MaxDistSet); ------debug--------*/

	/* initialize */
	InitializeRandoms();

	/* perform N runs */
	MaxNumThisRun = MaxTreatNum;		/*MaxTreatNum: global parameter*/
	CurrentFailed = 0;
	ForEach(i, 1, RandomTrials)
	{
		Improve = GetTreatments(MaxNumThisRun, MinTreatSize, MaxTreatSize, DistSet, MaxDistSet);
		/*begin debug output
		sprintf(Msg, "-------Trial:%d Improve=%d-------",i,Improve);
		Output(TreatSet, MaxTreat, Msg);
		sprintf(Msg, "---");
		Output(FailedRx, MaxFailedRx, Msg); 
		/*end debug output*/

		if ( ! Improve )
		{
			if ( ++CurrentFailed >= FutileTrials )	
				break;
			MaxNumThisRun += MaxTreatNum;
		}
		else
			CurrentFailed = 0;	/* number of futile trials in a row */
	}
	ActualTrials = i-1;

	/* output final treatments */
	sprintf(Msg, "%d Treatments learnt after %d random trials",MaxTreat+1,ActualTrials);
	Output(TreatSet, MaxTreat, Msg);
/*	sprintf(Msg, "**** Failed=%d",MaxFailedRx+1);
	Output(FailedRx, MaxFailedRx, Msg);*/
}

void Output(TreatItem *Set, int MaxSet, String Title)
{
	int i,j,att, val;
	float worth;

	printf("\n%s\n",Title);
	ForEach(i, 0, MaxSet)
	{
		worth=Set[i]._worth_data;
		printf("\n%2d worth=%f\t",i+1,worth);
		ForEach(j, 0, Set[i]._num)
		{
			att = Set[i]._candiSet[j]._att;
			val = Set[i]._candiSet[j]._val;
			printf("[%s=%s] ",AttName[att],AttValName[att][val]);
		}
	}
	printf("\n");

}

void OutputDist(DistItem *Set, int MaxSet)
{
	int i, weight, flag, att, val;
	double cdf;

	printf("\n Detailed Confidence1 Distribution info:\n");
	ForEach(i,0,MaxSet)
	{
		weight = Set[i]._weight;
		cdf = Set[i]._CDF;
		flag = Set[i]._flag;
		att = Set[i]._candiItem._att;
		val = Set[i]._candiItem._val;
		printf("%3d: C1=%8d, [%s=%s]\n",i,weight,AttName[att],AttValName[att][val]);
		/*printf("No%2d, w=%4d, cdf=%4f, flag=%d, [%s=%s]\n",i,weight,cdf,flag,AttName[att],AttValName[att][val]);*/
	}
}
