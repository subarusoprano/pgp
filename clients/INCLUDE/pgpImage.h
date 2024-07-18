/*____________________________________________________________________________
	Copyright (C) 1998 Network Associates, Inc.
	All rights reserved.
	
	pgpImage.h - header for PGP image index definitions
	

	$Id: pgpImage.h,v 1.15 1999/01/13 21:42:05 pbj Exp $
____________________________________________________________________________*/
#ifndef Included_pgpImage_h	/* [ */
#define Included_pgpImage_h


// bitmap images index definitions

#define IDX_NONE			-1
#define IDX_INVALID			0
#define IDX_PUSHED			1
#define IDX_VALID			2
#define IDX_VALIDPUSHED		3
#define IDX_AXIOMATIC		4
#define IDX_AXIOMATICPUSHED	5
#define IDX_RSAPUBKEY		6
#define IDX_RSAPUBDISKEY	7
#define IDX_RSAPUBREVKEY	8
#define IDX_RSAPUBEXPKEY	9
#define IDX_RSASECKEY		10
#define IDX_RSASECDISKEY	11
#define IDX_RSASECREVKEY	12
#define IDX_RSASECEXPKEY	13
#define IDX_RSASECSHRKEY	14
#define IDX_DSAPUBKEY		15
#define IDX_DSAPUBDISKEY	16
#define IDX_DSAPUBREVKEY	17
#define IDX_DSAPUBEXPKEY	18
#define IDX_DSASECKEY		19
#define IDX_DSASECDISKEY	20
#define IDX_DSASECREVKEY	21
#define IDX_DSASECEXPKEY	22
#define IDX_DSASECSHRKEY	23
#define IDX_RSAUSERID		24
#define IDX_DSAUSERID		25
#define IDX_INVALIDUSERID	26
#define IDX_PHOTOUSERID		27
#define IDX_CERT			28
#define IDX_REVCERT			29
#define IDX_EXPCERT			30
#define IDX_BADCERT			31
#define IDX_EXPORTCERT		32
#define IDX_METACERT		33
#define IDX_TRUSTEDCERT		34
#define IDX_GROUP			35
#define IDX_NOADK			36
#define	IDX_NOADKPUSHED		37
#define IDX_ADK				38
#define IDX_ADKPUSHED		39
#define IDX_OPENLOCK		40
#define IDX_CLOSEDLOCK		41
#define IDX_HEAD			42
#define IDX_X509CERT		43
#define IDX_X509EXPCERT		44
#define IDX_X509REVCERT		45
#define IDX_UNKNOWNKEY		46
//BEGIN ElGamal Sign SUPPORT - Imad R. Faiad
//#define NUM_BITMAPS			47
#define IDX_ELGPUBKEY		47
#define IDX_ELGPUBDISKEY	48
#define IDX_ELGPUBREVKEY	49
#define IDX_ELGPUBEXPKEY	50
#define IDX_ELGSECKEY		51
#define IDX_ELGSECDISKEY	52
#define IDX_ELGSECREVKEY	53
#define IDX_ELGSECEXPKEY	54
#define IDX_ELGSECSHRKEY	55
#define IDX_ELGUSERID		56
#define NUM_BITMAPS			57
//END ElGamal Sign SUPPORT

#endif /* ] Included_pgpImage_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/

