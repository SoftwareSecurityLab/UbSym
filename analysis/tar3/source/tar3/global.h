/*****************************************/
/*		Global data definition			 */
/*		-----------------------			 */
/*****************************************/

short 	MaxAtt,			/* max att number */
		MaxClass,		/* max class number */
		*MaxAttVal,		/* number of values for each att */
		*MaxAttNow,		/* number of values for each att in Now */
		*MaxAttChg;		/* number of values for each att in Changes */

long	MaxItem;		/* max data item number */
int		MaxTreat,		/* max treatment number */
		TreatSetSpace,	/* space allocated to TreatSet*/
		MaxDistSet,		/* max DistSet number */
		MaxFailedRx,	/* max FailedTreatSet number */
		FailedRxSpace;	/* space allocated to FailedRx */
				
BandInfo	*AttBand;	/* band info for each attribute */

Description	*Item;		/* data items */

TreatItem	*TreatSet,		/* treatment set */
			*FailedRx;		/* failed treatment set */

DistItem	*DistSet;		/* deltaf distribution set */

String	*ClassName,			/* class names */
  		*AttName,			/* att names */
  		**AttValName,		/* att value names */
		**AttValNow,		/* att value names in Now */
		**AttValChg,		/* att value names in Changes */
		FileName;			/* family name of files */

float	Baseline,			/* the baseline worth */
		MinWorth;			/* the baseline worth */

Boolean	ReverseClass;		/* flag of class order */
		
/*****************************************/
/*		Global parameter definition		 */
/*		---------------------------		 */
/*****************************************/

short	Granularity;		/* parameter indicate the percentile bands */

float	Step,				/* step factor for the score function */
		Skew;				/* option for skew/not skew the worth */

int		MaxTreatNum,		/* maximum treatment number */
		MinTreatSize,		/* minimum treatment size */
		MaxTreatSize,		/* maximum treatment size */
		FutileTrials,		/* maximum successive futile trials allowed */
		RandomTrials;		/* number of random trials conducted */