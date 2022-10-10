/*****************************************/
/*		Global data declaration			 */
/*		-----------------------			 */
/*****************************************/

extern  short 	MaxAtt,			/* max att number */
				MaxClass,		/* max class number */
				*MaxAttVal,		/* number of values for each att */
				*MaxAttNow,		/* number of values for each att in Now */
				*MaxAttChg;		/* number of values for each att in Changes*/

extern  long	MaxItem;		/* max data item number */
				
extern	int		MaxTreat,		/* max treatment number */
				TreatSetSpace,	/* space allocated to TreatSet*/
				MaxDistSet,		/* max DistSet number */
				MaxFailedRx,	/* max FailedTreatSet number */
				FailedRxSpace;	/* space allocated to FailedRx */


extern	BandInfo	*AttBand;	/* band info for each attribute */
				
extern  Description	*Item;		/* data items */

extern	DistItem	*DistSet;		/* deltaf distribution set */
					
extern  TreatItem	*TreatSet,		/* treatment set */
					*FailedRx;		/* failed treatment set */

extern  String	*ClassName,			/* class names */
		  		*AttName,			/* att names */
		  		**AttValName,		/* att value names */
				**AttValNow,		/* att value names in Now */
				**AttValChg,		/* att value names in Changes */
				FileName;			/* family name of files */

extern	float	Baseline,			/* the baseline worth */
				MinWorth;			/* the baseline worth */

extern	Boolean	ReverseClass;		/* flag of class order */


/*****************************************/
/*		Global parameter declaration	 */
/*		----------------------------	 */
/*****************************************/

extern	short	Granularity;		/* parameter indicate the percentile bands */

extern	float	Step,				/* step factor for the score function */
				Skew;				/* option for skew/not skew the worth */
extern	int		MaxTreatNum,		/* maximum treatment number */
				MinTreatSize,		/* minimum treatment size */
				MaxTreatSize,		/* maximum treatment size */
				FutileTrials,		/* maximum successive futile trials allowed */
				RandomTrials;		/* number of random trials conducted */