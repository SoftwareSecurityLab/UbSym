/************************************************/
/*									            */
/*  Print out xval summary					    */
/*	--------------------------			        */
/*												*/
/************************************************/

#include "defns.h"
#include "types.h"
#include "extern.h"


/************************************************/
/*									            */
/*  Fn is supposed to be "XDFxx"			    */
/*	--------------------------			        */
/*												*/
/************************************************/

void Summary(char* Fn)
{
	int i,j,TrialNo,Size,Att,Val;
	char Tmp[20];
	FILE	*Nf;

	strcpy(Tmp, Fn+3);
	TrialNo = atoi(Tmp);

	if ( TrialNo == 0 )
	{
		Nf = fopen( "XDFsum.out", "w" );
		fprintf(Nf,"---------------------------------------------\n");
		fprintf(Nf,"Summary of N-way cross validation experiments\n");
		fprintf(Nf,"---------------------------------------------\n");
		fprintf(Nf,"\tData file: %d cases * %d attributes\n\n",MaxItem+1,MaxAtt+1);
		fprintf(Nf,"\tParameter: granularity=%d\n",Granularity);
		fprintf(Nf,"\t           maxNumber=%d\n",MaxTreatNum);
		fprintf(Nf,"\t           minSize=%d\n",MinTreatSize);
		fprintf(Nf,"\t           maxSize=%d\n",MaxTreatSize);
		fprintf(Nf,"\t           randomTrials=%d\n",RandomTrials);
		fprintf(Nf,"\t           futileTrials=%d\n",FutileTrials);
		fprintf(Nf,"\t           bestClass=%5.2f%%\n",Skew*100);
		fprintf(Nf,"\n");
	}
	else
		Nf = fopen( "XDFsum.out", "a" );

	fprintf(Nf,"\n----- Trial %d: Treatments=%d -----",TrialNo,MaxTreat+1);
	ForEach(i, 0, MaxTreat)
	{
		fprintf(Nf,"\nworthOnData=%4f worthOnTest=%4f ",TreatSet[i]._worth_data,TreatSet[i]._worth_test);
		Size = TreatSet[i]._num;
		ForEach(j, 0, Size)
		{
			Att = TreatSet[i]._candiSet[j]._att;
			Val = TreatSet[i]._candiSet[j]._val;
			fprintf(Nf,"[%s=%s] ",AttName[Att],AttValName[Att][Val]);
		}
	}
	fprintf(Nf,"\n");

	fclose(Nf);
}