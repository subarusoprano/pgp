/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.
	
	$Id: pgpRecipientDialogCommon.cpp,v 1.35.6.1.8.2 1999/08/30 23:26:39 heller Exp $
____________________________________________________________________________*/

#include <ctype.h>
#include <string.h>

#include "pgpErrors.h"
#include "pgpKeys.h"
#include "pgpMem.h"
#include "pgpUtilities.h"

#include "pgpDialogs.h"
#include "pgpRecipientDialogCommon.h"

#define	UserIsVisible(user)												\
	( IsntNull( user ) &&												\
		( user->location == kPGPRecipientUserLocation_UserList ) ||		\
		( user->location == kPGPRecipientUserLocation_RecipientList ) )

#define kMandatoryARRMask		0x80
#define	IsMandatoryARRClass(x)	(((x) & kMandatoryARRMask) != 0)

	static PGPUInt32
GetNextMarkValue(void)
{
	static PGPUInt32	sMarkValue = 0;
	
	return( ++sMarkValue );
}

	static const char *
FindSubstring(
	const char * inBuffer,
	const char * inSearchStr)
{
	const char *	currBuffPointer = inBuffer;
	
	while (*currBuffPointer != 0)
	{
		const char * compareOne = currBuffPointer;
		const char * compareTwo = inSearchStr;
		
		while ( tolower(*compareOne) == tolower(*compareTwo) )
		{
			compareOne++;
			compareTwo++;
			if (*compareTwo == 0)
			{
				return (char *) currBuffPointer;
			}
		}
		currBuffPointer++;
	}
	return NULL;
}

	static PGPError
AllocateNewUsers(PGPRecipientsList *recipients)
{
	PGPError				err = kPGPError_NoErr;
	PGPRecipientUserList	*userList;
	
	userList = (PGPRecipientUserList *) PGPNewData( recipients->memoryMgr,
							sizeof( *userList ), 0 );
	if( IsntNull( userList ) )
	{
		PGPUInt32	userIndex;
		
		// Add user list to recipients.
		userList->nextUserList	= recipients->userLists;
		recipients->userLists	= userList;
	
		// Thread new users into recipients free list
		for( userIndex = 0; userIndex < kPGPNumUserListUsers; userIndex++ )
		{
			userList->users[userIndex].nextUser = recipients->freeUsers;
			recipients->freeUsers				= &userList->users[userIndex];
		}
	}
	else
	{
		err = kPGPError_OutOfMemory;
	}
	
	return( err );
}

	static PGPError
NewUser(
	PGPRecipientsList	*recipients,
	PGPRecipientUser	**newUser)
{
	PGPError	err = kPGPError_NoErr;
	
	*newUser = NULL;
	
	if( IsNull( recipients->freeUsers ) )
	{
		err = AllocateNewUsers( recipients );
	}
	
	if( IsntPGPError( err ) )
	{
		pgpAssert( IsntNull( recipients->freeUsers ) );
		
		*newUser				= recipients->freeUsers;
		recipients->freeUsers 	= recipients->freeUsers->nextUser;
		
		pgpClearMemory( *newUser, sizeof( **newUser ) );
		
		(**newUser).recipients = recipients;
	}
	
	return( err );
}

	static PGPError
AllocateNewKeys(PGPRecipientsList *recipients)
{
	PGPError			err = kPGPError_NoErr;
	PGPRecipientKeyList	*keyList;
	
	keyList = (PGPRecipientKeyList *) PGPNewData( recipients->memoryMgr,
							sizeof( *keyList ), 0 );
	if( IsntNull( keyList ) )
	{
		PGPUInt32	keyIndex;
		
		// Add key list to recipients.
		keyList->nextKeyList	= recipients->keyLists;
		recipients->keyLists	= keyList;
	
		// Thread new keys into recipients free list
		for( keyIndex = 0; keyIndex < kPGPNumKeyListKeys; keyIndex++ )
		{
			keyList->keys[keyIndex].nextKey = recipients->freeKeys;
			recipients->freeKeys			= &keyList->keys[keyIndex];
		}
	}
	else
	{
		err = kPGPError_OutOfMemory;
	}
	
	return( err );
}

	static PGPError
NewKey(
	PGPRecipientsList	*recipients,
	PGPRecipientKey		**newKey)
{
	PGPError	err = kPGPError_NoErr;
	
	*newKey = NULL;
	
	if( IsNull( recipients->freeKeys ) )
	{
		err = AllocateNewKeys( recipients );
	}
	
	if( IsntPGPError( err ) )
	{
		pgpAssert( IsntNull( recipients->freeKeys ) );

		*newKey 				= recipients->freeKeys;
		recipients->freeKeys 	= recipients->freeKeys->nextKey;
		
		pgpClearMemory( *newKey, sizeof( **newKey ) );
	}
	
	return( err );
}

	static void
FreeKey(PGPRecipientKey *key)
{
	pgpAssert( IsntNull( key ) );
	
	if( IsntNull( key->arrKeys ) )
	{
		PGPFreeData( key->arrKeys );
		key->arrKeys = NULL;
	}
	
	/* The key is not individually allocated, so no disposal is necessary */
}

	static PGPError
RememberName(
	PGPRecipientsList	*recipients,
	const char			*name,
	PGPUInt32			*nameOffset)
{
	PGPError	err = kPGPError_NoErr;
	PGPUInt32	nameLength;
	
	pgpAssert( IsntNull( recipients) );
	pgpAssert( IsntNull( name) );
	pgpAssert( IsntNull( nameOffset) );
	pgpAssert( recipients->nextNameOffset <= recipients->nameListSize );

	*nameOffset	= 0;
	nameLength 	= strlen( name ) + 1;	/* Account for trailing '\0' */

	/* Limit the names to 128 characters in case name is corrupted */
	if( nameLength > 128 )
		nameLength = 128;
	
	if( nameLength > recipients->nameListSize -
				recipients->nextNameOffset )
	{
		PGPUInt32	newNameListSize;
		char		*newNameList;
		
		// Need to grow/allocate the names list.
		
		#define kNameListGrowSize	1024L
	
		newNameListSize = recipients->nameListSize + kNameListGrowSize;
		
		newNameList = (char *) PGPNewData( recipients->memoryMgr,
									newNameListSize, 0 );
		if( IsntNull( newNameList ) )
		{
			if( IsntNull( recipients->nameList ) )
			{
				pgpCopyMemory( recipients->nameList, newNameList,
						recipients->nameListSize );
						
				PGPFreeData( recipients->nameList );
			}
			else
			{
				// Special case. Offset zero is invalid and is an empty string
				// Start at offset 1
				
				pgpAssert( recipients->nextNameOffset == 0 );
				
				recipients->nextNameOffset = 1;
				newNameList[0] = 0;
			}
			
			recipients->nameList 		= newNameList;
			recipients->nameListSize	= newNameListSize;
		}
		else
		{
			err = kPGPError_OutOfMemory;
		}
	}
	
	if( IsntPGPError( err ) )
	{
		pgpAssert( nameLength <= recipients->nameListSize -
										recipients->nextNameOffset );
		
		pgpCopyMemory( name, &recipients->nameList[recipients->nextNameOffset],
							nameLength );
		
		*nameOffset = recipients->nextNameOffset;
		recipients->nextNameOffset += nameLength;
	}
	
	return( err );
}

	static PGPError
FindARRKeys(
	PGPRecipientsList	*recipients,
	PGPRecipientKey		*theKey)
{
	PGPError	err = kPGPError_NoErr;
	
	if( IsntNull( theKey->arrKeys ) )
	{
		PGPFreeData( theKey->arrKeys );
		
		theKey->arrKeys 		= NULL;
		theKey->numARRKeys		= 0;
		theKey->haveMissingARRs	= FALSE;
	}
	
	if( recipients->arrEnforcement != kPGPARREnforcement_None )
	{
		PGPUInt32	numARRKeys;

		err = PGPCountAdditionalRecipientRequests( theKey->keyRef,
						&numARRKeys );
		if( IsntPGPError( err ) && numARRKeys != 0)
		{
			theKey->numARRKeys = (PGPUInt16) numARRKeys;

			theKey->arrKeys = (PGPRecipientKeyARRInfo *) PGPNewData(
										recipients->memoryMgr,
										theKey->numARRKeys *
										sizeof( theKey->arrKeys[0] ),
										kPGPMemoryMgrFlags_Clear );
			if( IsntNull( theKey->arrKeys ) )
			{
				PGPUInt32	arrIndex;
				
				for( arrIndex = 0; arrIndex < theKey->numARRKeys;
							++arrIndex )
				{
					PGPRecipientKeyARRInfo	*arrInfo;
					PGPKeyRef				arrKeyRef = kInvalidPGPKeyRef;
					
					arrInfo = &theKey->arrKeys[arrIndex];
					
					err = PGPGetIndexedAdditionalRecipientRequestKey(
								theKey->keyRef, recipients->keySet, arrIndex,
								&arrKeyRef, &arrInfo->keyID,
								&arrInfo->arrClass );
					if( IsntPGPError( err ) )
					{
						if( PGPKeyRefIsValid( arrKeyRef ) )
						{
							err = PGPGetKeyUserVal( arrKeyRef,
									(PGPUserValue *) &arrInfo->key );
						}
						
						if( IsNull( arrInfo->key ) )
						{
							arrInfo->keyMissing = TRUE;
						}
						else if( ! arrInfo->key->isVisible )
						{
							arrInfo->key = NULL;
						}
					
						if( IsMandatoryARRClass( arrInfo->arrClass ) &&
							IsNull( arrInfo->key ) )
						{
							theKey->haveMissingARRs = TRUE;
						}
					}
					
					if( IsPGPError( err ) )
					break;
				}
			}
			else
			{
				err = kPGPError_OutOfMemory;
			}
		}
	}
	
	return( err );
}

	static PGPError
UpdateKeyUserIDs(
	PGPRecipientsList	*recipients,
	PGPRecipientKey 	*theKey,
	PGPKeyIterRef		iterator,
	PGPUInt32			*numAddedUserIDs)
{
	PGPUserIDRef	curUserID;
	PGPError		err 				= kPGPError_NoErr;
	PGPBoolean		haveExistingUserIDs = IsntNull( theKey->users );
	PGPUserIDRef	primaryUserID		= kInvalidPGPUserIDRef;
	PGPUInt32		newNewUserIDs		= 0;
	
	(void) PGPKeyIterRewindUserID( iterator );
	(void) PGPGetPrimaryUserID( theKey->keyRef, &primaryUserID );
		
	err = PGPKeyIterNextUserID( iterator, &curUserID );
	while( IsntPGPError( err ) )
	{
		PGPRecipientUser	*user = NULL;
		
		if( haveExistingUserIDs )
		{
			/* See if we already have the user */
			user = theKey->users;
			while( IsntNull( user ) )
			{
				if( user->userInfo.userID == curUserID )
					break;
					
				user = user->nextUser;
			}
		}
		
		if( IsNull( user ) )
		{
			err = NewUser( recipients, &user );
			if( IsntPGPError( err ) )
			{
				PGPSize		bufferSize;
				char		tempName[ 256 ];
				PGPBoolean	isAttribute;
				
				user->kind				= kPGPRecipientUserKind_Key;
				user->userInfo.key 		= theKey;
				user->userInfo.userID	= curUserID;
				
				++newNewUserIDs;
				
				if( theKey->canEncrypt )
				{
					user->location =
							kPGPRecipientUserLocation_UserList;
				}
				else
				{
					user->location =
							kPGPRecipientUserLocation_Hidden;
				}
				
				if( curUserID == primaryUserID )
					user->userInfo.isPrimaryUser = TRUE;
				
				tempName[0] = 0;
				
				err = PGPGetUserIDBoolean( curUserID, 
							kPGPUserIDPropIsAttribute, &isAttribute );
				if( IsntPGPError( err ) )
				{
					if( isAttribute )
					{
						user->location = kPGPRecipientUserLocation_Hidden;
					}
					else
					{
						err = PGPGetUserIDStringBuffer( curUserID,
									kPGPUserIDPropName, sizeof( tempName ),
									tempName, &bufferSize );
						if( IsntPGPError( err ) ||
							err == kPGPError_BufferTooSmall )
						{
							err = RememberName( recipients, tempName, 
										&user->nameOffset );
						}
					}
				}
				
				if( IsntPGPError( err ) )
				{
					// Link the user to the key
					user->nextUser 	= theKey->users;
					theKey->users 	= user;
					
					if( UserIsVisible( user ) )
					{
						theKey->isVisible = TRUE;
						
						if( user->userInfo.isPrimaryUser )
						{
							theKey->primaryUser = user;
						}
						else if( IsNull( theKey->primaryUser ))
						{
							theKey->primaryUser = user;
						}
					}
				}
			}
		}
		
		if( IsntPGPError( err ) )
			err = PGPKeyIterNextUserID( iterator, &curUserID );
	}

	if( err == kPGPError_EndOfIteration )
		err = kPGPError_NoErr;
	
	if( IsntNull( numAddedUserIDs ) )
		*numAddedUserIDs = newNewUserIDs;
		
	return( err );
}

	static PGPError
AddKey(
	PGPRecipientsList	*recipients,
	PGPKeyIterRef		iterator,
	PGPKeyRef			keyRef,
	PGPBoolean			isDefaultKey,
	PGPBoolean			markAsNew,
	PGPRecipientKey		**recipientKey)
{
	PGPError			err = kPGPError_NoErr;
	PGPRecipientKey		*theKey;
	
	err = NewKey( recipients, &theKey );
	if( IsntPGPError( err ) )
	{
		theKey->keyRef				= keyRef;
		theKey->isDefaultKey		= isDefaultKey;
		theKey->isNewOrChangedKey	= markAsNew;
		theKey->isVisible			= FALSE;		/* Assume not visible */
		
		if( recipients->arrEnforcement != kPGPARREnforcement_None )
		{
			err = FindARRKeys( recipients, theKey );
		}
		
		if( IsntPGPError( err ) )
		{
			PGPInt32	algorithm;

			err = PGPGetKeyNumber( keyRef, kPGPKeyPropAlgID, &algorithm );
		
			theKey->algorithm = (PGPPublicKeyAlgorithm)algorithm;
		}
		
		if( IsntPGPError( err ) )
		{
			PGPBoolean	isAxiomaticKey;
			
			err = PGPGetKeyBoolean( keyRef, kPGPKeyPropIsAxiomatic,
								&isAxiomaticKey );
								
			theKey->isAxiomaticKey = isAxiomaticKey;
		}

		if( IsntPGPError( err ) )
		{
			PGPBoolean	isSecretKey;
			
			err = PGPGetKeyBoolean( keyRef, kPGPKeyPropIsSecret,
						&isSecretKey );
			
			theKey->isSecretKey = isSecretKey;
		}	
		
		if( IsntPGPError( err ) )
		{
			PGPBoolean	canEncrypt;
			
			err = PGPGetKeyBoolean( keyRef, kPGPKeyPropCanEncrypt,
						&canEncrypt );
								
			theKey->canEncrypt = canEncrypt;
		}

		if( IsntPGPError( err ) )
		{
			PGPInt32	keyBits;
			
			err = PGPGetKeyNumber( keyRef, kPGPKeyPropBits, &keyBits );

			theKey->keyBits = (PGPUInt16) keyBits;
		}
			
		if( IsntPGPError( err ) )
		{
			// Iterate our one-key set to the first key
			
//BEGIN
// need to add elgamal here (and RSAv4)
			PGPBoolean		bV3 = 0;
			if (IsPGPError(PGPGetKeyBoolean( keyRef, kPGPKeyPropIsV3, &bV3 )))
			    bV3 = 1;
//END
			if( theKey->algorithm == kPGPPublicKeyAlgorithm_DSA
//BEGIN
                || theKey->algorithm == kPGPPublicKeyAlgorithm_ElGamalSE
                || (theKey->algorithm == kPGPPublicKeyAlgorithm_RSA && !bV3)
//END
              )
			{
				PGPSubKeyRef	subKey;

				// Get the subkey to determine the
				// encryption key bits.
					
				err = PGPKeyIterNextSubKey( iterator, &subKey );
				if( IsntPGPError( err ) )
				{
					PGPInt32	keyBits;
					
					err = PGPGetSubKeyNumber( subKey, kPGPKeyPropBits,
								&keyBits );
					
					theKey->subKeyBits = (PGPUInt16) keyBits;
				}
				
				if( err == kPGPError_EndOfIteration )
					err = kPGPError_NoErr;
			}
			
			if( IsntPGPError( err ) )
			{
				err = UpdateKeyUserIDs( recipients, theKey, iterator, NULL );
			}
		}
		
		if( IsntPGPError( err ) )
		{
			pgpAssert( IsntNull( theKey->users ) );
			
			// Set the primary user to the first user in the list if
			// no explicit or visible primary user was found.
			
			if( IsNull( theKey->primaryUser ) )
				theKey->primaryUser = theKey->users;
				
			// Finally, link key into the list
			theKey->nextKey		= recipients->keys;
			recipients->keys	= theKey;
		}
		else
		{	
			FreeKey( theKey );
			theKey = NULL;
		}
	}
	
	*recipientKey = theKey;
	
	return( err );
}

	static PGPError
UpdateDynamicRecipientValues(PGPRecipientsList *recipients)
{
	PGPRecipientKey		*curKey;
	PGPRecipientUser	*curUser;
	PGPError			err = kPGPError_NoErr;
	
	curKey = recipients->keys;
	while( IsntNull( curKey ) && IsntPGPError( err ) )
	{
		curUser = curKey->users;
		while( IsntNull( curUser ) )
		{
			PGPInt32	userValidity;
							
			if( IsntPGPError( PGPGetUserIDNumber( curUser->userInfo.userID,
							kPGPUserIDPropValidity, &userValidity ) ) )
			{
				curUser->validity = (PGPValidity) userValidity;
			}
			else
			{
				curUser->validity = kPGPValidity_Invalid;
			}
								
			curUser = curUser->nextUser;
		}
		
		if( recipients->arrEnforcement != kPGPARREnforcement_None )
		{
			err = FindARRKeys( recipients, curKey );
			if( IsPGPError( err ) )
				break;
		}
		
		curKey = curKey->nextKey;
	}

	curUser = recipients->groups;
	while( IsntNull( curUser ) && IsntPGPError( err ) )
	{
		PGPUInt32	groupItemIndex;
		
		curUser->validity 					= kPGPValidity_Complete;
		curUser->groupInfo.numMissingKeys	= 0;
		curUser->groupInfo.haveMissingARRs 	= FALSE;
		curUser->groupInfo.numARRKeys		= 0;
		
		for( groupItemIndex = 0; groupItemIndex < curUser->groupInfo.numKeys;
					++groupItemIndex )
		{
			PGPGroupItem	item;
			
			err = PGPGetIndGroupItem( recipients->groupSet,
						curUser->groupInfo.groupID, groupItemIndex, &item );
			if( IsntPGPError( err ) )
			{
				PGPRecipientKey	*key = NULL;

				if( item.userValue == NULL )
				{
					PGPKeyRef	theKey;
					
					if( IsntPGPError( PGPGetKeyByKeyID( recipients->keySet,
										&item.u.key.keyID,
										item.u.key.algorithm, &theKey ) ) )
					{
						err = PGPGetKeyUserVal( theKey,
									(PGPUserValue *) &key );
					}
					
					if( IsntPGPError( err ) && IsntNull( key ) )
					{
						err = PGPSetIndGroupItemUserValue( recipients->groupSet,
									curUser->groupInfo.groupID, groupItemIndex,
									(PGPUserValue) key );
					}
				}
				else
				{
					key = (PGPRecipientKey *) item.userValue;
				}
				
				if( IsntNull( key ) )
				{
					if( key->primaryUser->validity < curUser->validity )
						curUser->validity = key->primaryUser->validity;
						
					if( key->haveMissingARRs )
						curUser->groupInfo.haveMissingARRs = TRUE;
						
					curUser->groupInfo.numARRKeys += key->numARRKeys;
				}
				else
				{
					++curUser->groupInfo.numMissingKeys;
				}
			}
			
			if( IsPGPError( err ) )
				break;
		}
	
		curUser = curUser->nextUser;
	}
	
	return( err );
}

	static PGPError
UpdateNewKeys(
	PGPRecipientsList	*recipients,
	PGPBoolean			markAsNew)
{
	PGPError		err;
	PGPKeyListRef	keyList;

	err = PGPOrderKeySet( recipients->keySet, kPGPAnyOrdering, &keyList );
	if( IsntPGPError( err ) )
	{
		PGPKeyIterRef	iterator;
		PGPKeyRef		defaultKey = kInvalidPGPKeyRef;
		
		(void) PGPGetDefaultPrivateKey( recipients->keySet, &defaultKey );

		err = PGPNewKeyIter( keyList, &iterator );
		if( IsntPGPError( err ) )
		{
			PGPKeyRef	theKey;
			
			err = PGPKeyIterNext( iterator, &theKey );
			while( IsntPGPError( err ) )
			{
				PGPRecipientKey	*recipientKey;

				err = PGPGetKeyUserVal( theKey,
								(PGPUserValue *) &recipientKey );
				if( IsntPGPError( err ) )
				{
					if( IsNull( recipientKey ) )
					{
						PGPBoolean	isDefault = ( theKey == defaultKey );
					
						err = AddKey( recipients, iterator, theKey, isDefault,
									markAsNew, &recipientKey );
						if( IsntPGPError( err ) )
						{
							err = PGPSetKeyUserVal( theKey, recipientKey );
						}
					}
					else
					{
						PGPUInt32	newNewUserIDs;
						
						err = UpdateKeyUserIDs( recipients, recipientKey, iterator, &newNewUserIDs );
						if( IsntPGPError( err ) && newNewUserIDs != 0 )
						{
							recipientKey->isNewOrChangedKey = TRUE;
						}
					}
				}
				
				if( IsntPGPError( err ) )
				{
					err = PGPKeyIterNext( iterator, &theKey );
				}
			}
			
			if( err == kPGPError_EndOfIteration )
				err = kPGPError_NoErr;
				
			PGPFreeKeyIter( iterator );
		}
		
		PGPFreeKeyList( keyList );
	}
	
	return( err );
}

	static PGPError
AddKeySet(
	PGPRecipientsList	*recipients,
	PGPKeySetRef		keySet)
{
	pgpAssert( ! PGPKeySetRefIsValid( recipients->keySet ) );
	
	recipients->keySet = keySet;
	
	return( UpdateNewKeys( recipients, FALSE ) );
}

	static PGPError
AddNewKeys(
	PGPRecipientsList	*recipients,
	PGPKeySetRef		keySet)
{
	PGPError	err;
	
	err = PGPAddKeys( keySet, recipients->keySet );
	if( IsntPGPError( err ) )
	{
		err = PGPCheckKeyRingSigs( keySet, recipients->keySet,
				FALSE, NULL, 0 );
		if( IsntPGPError( err ) )
		{
			err = PGPPropagateTrust( recipients->keySet );
			if( IsntPGPError( err ) )
			{
				err = PGPCommitKeyRingChanges( recipients->keySet );
				if( IsntPGPError( err ) )
				{
					err = UpdateNewKeys( recipients, TRUE );
					if( IsntPGPError( err ) )
					{
						err = UpdateDynamicRecipientValues( recipients );
					}
				}
			}
		}
	}
	
	return( err );
}

	static PGPError
AddGroup(
	PGPRecipientsList	*recipients,
	PGPGroupSetRef		groupSet,
	PGPGroupID			groupID)
{
	PGPError			err;
	PGPRecipientUser	*user;
	
	err = NewUser( recipients, &user );
	if( IsntPGPError( err ) )
	{
		user->kind = kPGPRecipientUserKind_Group;
		
		err = PGPNewFlattenedGroupFromGroup( groupSet, groupID,
					recipients->groupSet, &user->groupInfo.groupID );
		if( IsntPGPError( err ) )
		{
			err = PGPCountGroupItems( recipients->groupSet,
						user->groupInfo.groupID, TRUE,
						&user->groupInfo.numKeys, NULL );
			if( IsntPGPError( err ) && user->groupInfo.numKeys > 0 )
			{
				PGPGroupInfo	info;
			
				err	= PGPGetGroupInfo( groupSet, groupID, &info );
				if( IsntPGPError( err ) )
				{
					err = RememberName( recipients, info.name,
								&user->nameOffset );
				}
			}
		}
		
		if( IsntPGPError( err ) )
		{
			if( user->groupInfo.numKeys > 0 )
			{
				user->location = kPGPRecipientUserLocation_UserList;
			}
			else
			{
				user->location = kPGPRecipientUserLocation_Hidden;
			}
			
			user->nextUser 		= recipients->groups;
			recipients->groups 	= user;
		}
	}
							
	return( err );
}

	static PGPError
AddGroupSet(
	PGPContextRef		context,
	PGPRecipientsList	*recipients,
	PGPGroupSetRef		groupSet)
{
	PGPUInt32	numGroups;
	PGPError	err;
	
	err = PGPNewGroupSet( context, &recipients->groupSet );
	if( IsntPGPError( err ) )
	{
		err	= PGPCountGroupsInSet( groupSet, &numGroups );
		if( IsntPGPError( err ) )
		{
			PGPUInt32	index;
			
			for( index = 0; index < numGroups; ++index )
			{
				PGPGroupID	groupID;
				
				err	= PGPGetIndGroupID( groupSet, index, &groupID );
				if ( IsntPGPError( err ) )
				{
					err = AddGroup( recipients, groupSet, groupID );
				}
				
				if ( IsPGPError( err ) )
					break;
			}
		}
	}
	
	return( err );
}

	static PGPRecipientKey *
FindKeyFromKeyRef(
	const PGPRecipientsList		*recipients,
	PGPKeyRef					searchKeyRef)
{
	PGPRecipientKey	*curKey;

	curKey = recipients->keys;
	while( IsntNull( curKey ) )
	{
		if( PGPCompareKeys( curKey->keyRef, searchKeyRef,
					kPGPKeyIDOrdering ) == 0 )
			break;
		
		curKey = curKey->nextKey;
	}

	return( curKey );
}

/* Must use PGPFreeData to dispose of foundUsers */

	static PGPError
FindUsersFromUserID(
	PGPRecipientsList	*recipients,
	const char			*userID,
	PGPBoolean			matchBestSecretKey,
	PGPUInt32			*numFoundUsers,
	PGPRecipientUser	***foundUsers)
{
	PGPError			err = kPGPError_NoErr;
	PGPRecipientKey		*curKey;
	PGPRecipientKey		*bestSecretKey;
	PGPRecipientUser	*curUser;
	PGPUInt32			markValue;
	
	*numFoundUsers 	= 0;
	*foundUsers		= NULL;
	bestSecretKey	= NULL;
	markValue		= GetNextMarkValue();
	
	/* Tabulate and mark matches first */
	curKey = recipients->keys;
	while( IsntNull( curKey ) )
	{
		PGPRecipientUser	*foundUser = NULL;

		curUser = curKey->users;
		while( IsntNull( curUser ) )
		{
			if( UserIsVisible( curUser ) && 
				IsntNull( FindSubstring( PGPGetRecipientUserNamePtr( curUser ),
								userID ) ) )
			{
				if( curUser->userInfo.isPrimaryUser)
				{
					foundUser = curUser;
					break;
				}
				else if( IsNull( foundUser ) )
				{
					foundUser = curUser;
				}
			}
		
			curUser = curUser->nextUser;
		}
		
		if( IsntNull( foundUser ) )
		{
			if( curKey->isSecretKey && matchBestSecretKey )
			{
				// The best secret key is (1) the default key or
				// (2) a DH/DSA key instead of anything else
				
				if( IsNull( bestSecretKey ) )
				{
					bestSecretKey = curKey;
				}
				else
				{	
					PGPBoolean	switchBestKey = FALSE;
					
					if( curKey->isDefaultKey )
					{
						pgpAssert( ! bestSecretKey->isDefaultKey );
						
						switchBestKey = TRUE;
					}
					else if( curKey->algorithm ==
									kPGPPublicKeyAlgorithm_DSA &&
							 bestSecretKey->algorithm !=
							 		kPGPPublicKeyAlgorithm_DSA )
					{
						switchBestKey = TRUE;
					}
					
					if( switchBestKey )
					{
						bestSecretKey->markValue 	= 0;
						*numFoundUsers 				-= 1;
						
						bestSecretKey = curKey;
					}
					else
					{
						// bestSecretKey is a better match. Skip this one.
						foundUser = NULL;
					}
				}
			}
		}
		
		if( IsntNull( foundUser ) )
		{
			foundUser->markValue	= markValue;
			curKey->markValue 		= markValue;
		
			*numFoundUsers += 1;
		}
		
		curKey = curKey->nextKey;
	}

	curUser = recipients->groups;
	while( IsntNull( curUser ) )
	{
		if( UserIsVisible( curUser ) )
		{
			char	groupUserID[256];
			
			/* Surround the group name with "<>" to simulate an email address */
			
			strcpy( groupUserID, "<" );
			strcat( groupUserID, PGPGetRecipientUserNamePtr( curUser ) );
			strcat( groupUserID, ">" );
			
			if( IsntNull( FindSubstring( groupUserID, userID ) ) )
			{
				curUser->markValue = markValue;
				*numFoundUsers += 1;
			}	
		}
	
		curUser = curUser->nextUser;
	}
	
	*foundUsers = (PGPRecipientUser **) PGPNewData( recipients->memoryMgr,
								*numFoundUsers * sizeof( **foundUsers ),
								kPGPMemoryMgrFlags_Clear );
	if( IsntNull( *foundUsers ) )
	{
		PGPUInt32	userIndex = 0;
		
		curKey = recipients->keys;
		while( IsntNull( curKey ) )
		{
			if( curKey->markValue == markValue )
			{
				curUser = curKey->users;
				while( IsntNull( curUser ) )
				{
					if( curUser->markValue == markValue )
					{
						(*foundUsers)[userIndex] = curUser;
						++userIndex;
					}
				
					curUser = curUser->nextUser;
				}
			}
			
			curKey = curKey->nextKey;
		}

		curUser = recipients->groups;
		while( IsntNull( curUser ) )
		{
			if( curUser->markValue == markValue )
			{
				(*foundUsers)[userIndex] = curUser;
				++userIndex;
			}
		
			curUser = curUser->nextUser;
		}
	}
	else
	{
		err = kPGPError_OutOfMemory;
	}
	
	return( err );
}

	static PGPError
FindUserFromKeyID(
	PGPRecipientsList		*recipients,
	const PGPKeyID			*searchKeyID,
	PGPPublicKeyAlgorithm	searchAlgorithm,
	PGPRecipientUser		**foundUser)
{
	PGPError			err = kPGPError_NoErr;
	PGPRecipientKey		*curKey;
	
	*foundUser = NULL;
	
	curKey = recipients->keys;
	while( IsntNull( curKey ) && IsntPGPError( err ) )
	{
		PGPKeyID	keyID;
		
		err = PGPGetKeyIDFromKey( curKey->keyRef, &keyID );
		if( IsntPGPError( err ) &&
			PGPCompareKeyIDs( &keyID, searchKeyID ) == 0 &&
			curKey->algorithm == searchAlgorithm )
		{
			if( UserIsVisible( curKey->primaryUser ) )
			{
				*foundUser = curKey->primaryUser;
			}
			
			break;
		}
		
		curKey = curKey->nextKey;
	}
	
	return( err );
}

	static PGPError
AddMissingRecipient(
	PGPRecipientsList		*recipients,
	const PGPRecipientSpec	*spec)	// Assumed client allocated
{
	PGPRecipientUser	*user;
	PGPError			err;
	
	err = NewUser( recipients, &user );
	if( IsntPGPError( err ) )
	{
		char	userIDString[256];
		
		user->kind 				= kPGPRecipientUserKind_MissingRecipient;
		user->location 			= kPGPRecipientUserLocation_RecipientList;
		user->missingUser.type 	= spec->type;
		
		if( spec->locked )
			++user->lockRefCount;
		
		switch( spec->type )
		{
			case kPGPRecipientSpecType_UserID:
				strcpy( userIDString, spec->u.userIDStr );
				break;
			
			case kPGPRecipientSpecType_KeyID:
				user->missingUser.keyID		= &spec->u.id.keyID;
				user->missingUser.algorithm	= spec->u.id.algorithm;
				
				err = pgpGetMissingRecipientKeyIDStringPlatform(
							recipients->context, &spec->u.id.keyID,
							userIDString );
				break;
			
			default:
				pgpDebugMsg( "Unknown recipient type" );
				break;
		}

		if( IsntPGPError( err ) )
		{
			err = RememberName( recipients, userIDString, &user->nameOffset );
			if( IsntPGPError( err ) )
			{
				user->nextUser = recipients->missingRecipients;
				recipients->missingRecipients = user;
			}
		}
	}
	
	// Don't need to free user upon error because it is in a larger,
	// allocated block which is freed as a single item
	
	return( err );
}

	static PGPError
MoveDefaultRecipients(
	PGPRecipientsList		*recipients,
	PGPUInt32				numDefaultRecipients,
	const PGPRecipientSpec	defaultRecipients[],
	PGPBoolean				*movedARRs)
{
	PGPError	err = kPGPError_NoErr;
	PGPUInt32	recipientIndex;
	
	*movedARRs = FALSE;
	
	for( recipientIndex = 0; recipientIndex < numDefaultRecipients;
				recipientIndex++ )
	{
		const PGPRecipientSpec	*curRecipient;
		PGPBoolean				movedAnARR = FALSE;
		
		curRecipient = &defaultRecipients[recipientIndex];
		
		switch( curRecipient->type )
		{
			case kPGPRecipientSpecType_Key:
			case kPGPRecipientSpecType_KeyID:
			{
				PGPKeyRef		theKey = kInvalidPGPKeyRef;
				
				if( curRecipient->type == kPGPRecipientSpecType_Key )
				{
					theKey = curRecipient->u.key;
				}
				else
				{
					(void) PGPGetKeyByKeyID( recipients->keySet,
								&curRecipient->u.id.keyID,
								curRecipient->u.id.algorithm, &theKey );
				}
				
				if( PGPKeyRefIsValid( theKey ) )
				{
					PGPRecipientKey	*key;

					key = FindKeyFromKeyRef( recipients, theKey );
					if( IsntNull( key ) && key->isVisible &&
						IsntNull( key->primaryUser ) )
					{
						PGPUInt32	numMovedUsers;
						
						err = PGPMoveRecipients( recipients,
									kPGPRecipientUserLocation_RecipientList,
									1, &key->primaryUser, &numMovedUsers,
									&movedAnARR );
						
						if( curRecipient->locked )
							++key->primaryUser->lockRefCount;
					}
				}
				else
				{
					err = AddMissingRecipient( recipients, curRecipient );
				}
				
				break;
			}
			
			case kPGPRecipientSpecType_UserID:
			{
				PGPUInt32			numMovedUsers = 0;
				PGPUInt32			numMatchedUsers;
				PGPRecipientUser	**matchedUserList;
				
				err = FindUsersFromUserID( recipients,
							curRecipient->u.userIDStr, TRUE, &numMatchedUsers,
							&matchedUserList );
				if( IsntPGPError( err ) )
				{
					if( numMatchedUsers != 0 )
					{
						err = PGPMoveRecipients( recipients,
								kPGPRecipientUserLocation_RecipientList,
								numMatchedUsers, matchedUserList,
								&numMovedUsers, &movedAnARR );
					
						if( numMatchedUsers == 1 )
						{
							if( curRecipient->locked )
								++matchedUserList[0]->lockRefCount;
						}
						else
						{
							PGPUInt32	userIndex;
							
							for( userIndex = 0; userIndex < numMatchedUsers;
									++userIndex )
							{
								matchedUserList[userIndex]->multipleMatch =
										TRUE;
							}
						}
					}
					else
					{
						err = AddMissingRecipient( recipients, curRecipient );
					}
					
					PGPFreeData( matchedUserList );
				}
				
				break;
			}
			
			default:
				pgpDebugMsg(
					"MoveDefaultRecipients(): Unknown PGPRecipientSpecType" );
				err = kPGPError_BadParams;
				break;
		}
		
		if( IsPGPError( err ) )
			break;
			
		if( movedAnARR )
			*movedARRs = TRUE;
	}

	return( err );
}
	
	const char *
PGPGetRecipientUserNamePtr(
	const PGPRecipientUser *user)
{
	pgpAssert( IsntNull( user ) );
	
	return( &user->recipients->nameList[user->nameOffset] );
}

	void
PGPGetRecipientUserName(
	const PGPRecipientUser 	*user,
	char					name[256])
{
	pgpAssert( IsntNull( user ) );
	pgpAssert( IsntNull( name ) );
	
	strcpy( name, PGPGetRecipientUserNamePtr( user ) );
}

	PGPError
PGPBuildRecipientsList(
	void *							hwndParent,
	PGPContextRef					context,
	PGPKeySetRef					allKeys,
	PGPGroupSetRef					groupSet,
	PGPUInt32						numDefaultRecipients,
	const PGPRecipientSpec			*defaultRecipients,
	PGPUInt32						serverCount,
	const PGPKeyServerSpec			*serverList,
	PGPtlsContextRef				tlsContext,
	PGPBoolean						syncUnknownKeys,
	PGPAdditionalRecipientRequestEnforcement	arrEnforcement,
	PGPRecipientEventHandlerProcPtr	eventHandler,
	PGPUserValue					eventUserValue,
	PGPRecipientsList				*recipients,
	PGPBoolean						*haveDefaultARRs)
{
	PGPError	err = kPGPError_NoErr;
	
	pgpAssert( PGPContextRefIsValid( context ) );
	pgpAssert( PGPKeySetRefIsValid( allKeys ) );
	pgpAssert( IsntNull( recipients ) );

	pgpClearMemory( recipients, sizeof( *recipients ) );

	recipients->context			= context;
	recipients->memoryMgr		= PGPGetContextMemoryMgr( context );
	recipients->arrEnforcement	= arrEnforcement;
	recipients->eventHandler	= eventHandler;
	recipients->eventUserValue	= eventUserValue;
	recipients->serverList		= serverList;
	recipients->serverCount		= serverCount;
	recipients->tlsContext		= tlsContext;
	
	*haveDefaultARRs = FALSE;
	
	err = AddKeySet( recipients, allKeys );
	if( IsntPGPError( err ) && PGPGroupSetRefIsValid( groupSet ) )
	{
		err = AddGroupSet( context, recipients, groupSet );
	}
	
	if( IsntPGPError( err ) )
	{
		err = UpdateDynamicRecipientValues( recipients );
	}

	if( IsntPGPError( err ) && numDefaultRecipients != 0 )
	{
		err = MoveDefaultRecipients( recipients, numDefaultRecipients,
						defaultRecipients, haveDefaultARRs );
	}

	if( IsntPGPError( err ) && syncUnknownKeys )
	{
		PGPBoolean	haveNewKeys;
		
		err = PGPUpdateMissingRecipients( hwndParent, recipients,
					&haveNewKeys );
	}

	return( err );
}

	void
PGPDisposeRecipientsList(PGPRecipientsList *recipients)
{
	PGPRecipientKeyList		*curKeyList;
	PGPRecipientUserList	*curUserList;
	PGPRecipientKey			*curKey;
	
	pgpAssert( IsntNull( recipients ) );
	pgpAssert( PGPContextRefIsValid( recipients->context ) );
	pgpAssert( PGPMemoryMgrRefIsValid( recipients->memoryMgr ) );
	
	curKey = recipients->keys;
	while( IsntNull( curKey ) )
	{
		FreeKey( curKey );
		
		curKey = curKey->nextKey;
	}
	
	curKeyList = recipients->keyLists;
	while( IsntNull( curKeyList ) )
	{
		PGPRecipientKeyList	*nextKeyList;
	
		nextKeyList = curKeyList->nextKeyList;
			PGPFreeData( curKeyList );
		curKeyList = nextKeyList;
	}

	curUserList = recipients->userLists;
	while( IsntNull( curUserList ) )
	{
		PGPRecipientUserList	*nextUserList;
	
		nextUserList = curUserList->nextUserList;
			PGPFreeData( curUserList );
		curUserList = nextUserList;
	}
	
	if( IsntNull( recipients->nameList ) )
		PGPFreeData( recipients->nameList );
	
	if( PGPGroupSetRefIsValid( recipients->groupSet ) )
		PGPFreeGroupSet( recipients->groupSet );
		
	pgpClearMemory( recipients, sizeof( *recipients ) );
}

	static PGPError
SendUserEvent(
	PGPRecipientsList		*recipients,
	PGPRecipientEventType	eventType,
	PGPRecipientUser		*user)
{
	PGPError	err = kPGPError_NoErr;
	
	if( IsntNull( recipients->eventHandler ) )
	{
		PGPRecipientEvent	event;
		
		pgpClearMemory( &event, sizeof( event ) );
		
		event.type  = eventType;
		event.user 	= user;
	
		err = (*recipients->eventHandler)( recipients, &event,
						recipients->eventUserValue ); 
	}

	return( err );
}

	static PGPBoolean
MarkKeyARRsForUserToRecipientMove(
	PGPRecipientsList	*recipients,
	PGPRecipientKey		*key,
	PGPUInt32			markValue,
	PGPBoolean			*markedARRs,
	PGPBoolean			*missingARRs)
{
	PGPBoolean		moveUser;
	
	pgpAssert( recipients->arrEnforcement != kPGPARREnforcement_None );

	moveUser 		= TRUE;
	*missingARRs 	= FALSE;
	*markedARRs		= FALSE;
	
	if( key->numARRKeys != 0 )
	{
		PGPBoolean	markARRs = TRUE;
		
		if( key->haveMissingARRs )
		{
			*missingARRs = TRUE;
			
			/*
			** In the strict case, the user cannot be moved because an ARR
			** was not found. In the warn case, we move what we can.
			*/
			
			if( recipients->arrEnforcement == kPGPARREnforcement_Strict )
			{
				moveUser = FALSE;
				markARRs = FALSE;
			}
		}
		
		if( markARRs )
		{
			PGPUInt32	arrIndex;
			
			for( arrIndex = 0; arrIndex < key->numARRKeys; arrIndex++ )
			{
				PGPRecipientKeyARRInfo	*arrInfo;
				
				arrInfo = &key->arrKeys[arrIndex];
				if( IsntNull( arrInfo->key ) )
				{
					PGPRecipientUser	*user = arrInfo->key->primaryUser;
					
					pgpAssert( arrInfo->key->isVisible );
					
					++user->userInfo.arrRefCount;
					user->markValue = markValue;

					*markedARRs = TRUE;
					
					if( IsMandatoryARRClass( arrInfo->arrClass ) )
					{
						++user->userInfo.enforcedARRRefCount;
						
						if( recipients->arrEnforcement ==
								kPGPARREnforcement_Strict)
						{
							++user->lockRefCount;
						}
					}
				}
			}
		}
	}
	
	return( moveUser );
}

	static void
MarkKeyARRsForRecipientToUserMove(
	PGPRecipientsList	*recipients,
	PGPRecipientKey		*key,
	PGPUInt32			markValue)
{
	(void) recipients;

	pgpAssert( recipients->arrEnforcement != kPGPARREnforcement_None );

	if( key->numARRKeys != 0 )
	{
		PGPUInt32	arrIndex;
		
		for( arrIndex = 0; arrIndex < key->numARRKeys; arrIndex++ )
		{
			PGPRecipientKeyARRInfo	*arrInfo;
			
			arrInfo = &key->arrKeys[arrIndex];
			if( IsntNull( arrInfo->key ) )
			{
				PGPRecipientKey		*arrKey 	= arrInfo->key;
				PGPRecipientUser	*arrUser	= arrKey->primaryUser;
				
				pgpAssert( arrKey->isVisible );
				pgpAssert( arrUser->userInfo.arrRefCount != 0 );
				
				if( IsMandatoryARRClass( arrInfo->arrClass ) )
				{
					--arrUser->userInfo.enforcedARRRefCount;
					
					if( recipients->arrEnforcement ==
								kPGPARREnforcement_Strict)
					{
						--arrUser->lockRefCount;
					}
				}
				
				--arrUser->userInfo.arrRefCount;
				if( arrUser->userInfo.arrRefCount == 0 )
				{
					if( ! arrUser->movedManually )
					{
						arrUser->markValue = markValue;
					}
				}
			}
		}
	}
}

	static PGPBoolean
MarkGroupARRsForUserToRecipientMove(
	PGPRecipientsList	*recipients,
	PGPRecipientUser	*group,
	PGPUInt32			markValue,
	PGPBoolean			*markedARRs,
	PGPBoolean			*missingARRs)
{
	PGPBoolean		moveGroup;
	
	pgpAssert( recipients->arrEnforcement != kPGPARREnforcement_None );
	pgpAssert( group->kind == kPGPRecipientUserKind_Group );

	moveGroup 		= TRUE;
	*missingARRs 	= FALSE;
	*markedARRs		= FALSE;
	
	if( group->groupInfo.numARRKeys != 0 )
	{
		PGPBoolean	markARRs = TRUE;
		
		if( group->groupInfo.haveMissingARRs )
		{
			*missingARRs = TRUE;
			
			/*
			** In the strict case, the group cannot be moved because an ARR
			** was not found. In the warn case, we move what we can.
			*/
			
			if( recipients->arrEnforcement == kPGPARREnforcement_Strict )
			{
				moveGroup = FALSE;
				markARRs = FALSE;
			}
		}
		
		if( markARRs )
		{
			PGPUInt32	groupItemIndex;
			
			for( groupItemIndex = 0;
					groupItemIndex < group->groupInfo.numKeys;
						++groupItemIndex )
			{
				PGPGroupItem	item;
				PGPError		err;
				
				err = PGPGetIndGroupItem( recipients->groupSet,
							group->groupInfo.groupID, groupItemIndex, &item );
				pgpAssertNoErr( err );
				if( IsntPGPError( err ) )
				{
					PGPRecipientKey	*key = NULL;

					key = (PGPRecipientKey *) item.userValue;
					if( IsntNull( key ) )
					{
						PGPBoolean	keyMissingARRs;
						
						(void) MarkKeyARRsForUserToRecipientMove(
									recipients,
									key, markValue, markedARRs,
									&keyMissingARRs );
									
						if( keyMissingARRs )
							*missingARRs = TRUE;
					}
				}
			}
		}
	}
	
	return( moveGroup );
}

	static void
MarkGroupARRsForRecipientToUserMove(
	PGPRecipientsList	*recipients,
	PGPRecipientUser	*group,
	PGPUInt32			markValue)
{
	pgpAssert( recipients->arrEnforcement != kPGPARREnforcement_None );
	pgpAssert( group->kind == kPGPRecipientUserKind_Group );

	if( group->groupInfo.numARRKeys != 0 )
	{
		PGPUInt32	groupItemIndex;
		
		for( groupItemIndex = 0; groupItemIndex < group->groupInfo.numKeys;
					++groupItemIndex )
		{
			PGPGroupItem	item;
			PGPError		err;
			
			err = PGPGetIndGroupItem( recipients->groupSet,
						group->groupInfo.groupID, groupItemIndex, &item );
			pgpAssertNoErr( err );
			if( IsntPGPError( err ) )
			{
				PGPRecipientKey	*key = NULL;

				key = (PGPRecipientKey *) item.userValue;
				if( IsntNull( key ) )
				{
					(void) MarkKeyARRsForRecipientToUserMove( recipients,
								key, markValue );
				}
			}
		}
	}
}

	PGPError
PGPMoveRecipients(
	PGPRecipientsList			*recipients,
	PGPRecipientUserLocation	destinationList,
	PGPUInt32					numUsers,
	PGPRecipientUser			**userList,
	PGPUInt32					*numMovedUsers,
	PGPBoolean					*movedARRs)
{
	PGPError			err = kPGPError_NoErr;
	PGPUInt32			userIndex;
	PGPUInt32			markValue;
	PGPRecipientKey		*curKey;
	PGPRecipientUser	*curUser;
	
	pgpAssert(	destinationList == kPGPRecipientUserLocation_UserList ||
				destinationList == kPGPRecipientUserLocation_RecipientList );
	pgpAssert( numUsers > 0 );
	pgpAssert( IsntNull( userList ) );
	pgpAssert( IsntNull( numMovedUsers ) );
	
	*numMovedUsers 	= 0;
	*movedARRs		= FALSE;
	
	markValue = GetNextMarkValue();

	/* First pass. Mark items to move and skip/remove invalid items */
	for( userIndex = 0; userIndex < numUsers; userIndex++ )
	{
		curUser = userList[userIndex];
		
		pgpAssert( UserIsVisible( curUser ) );
		pgpAssert( curUser->location != destinationList );

		if( curUser->lockRefCount > 0 )
		{
			pgpAssert(
				curUser->location == kPGPRecipientUserLocation_RecipientList );
		}
		else if( curUser->kind == kPGPRecipientUserKind_MissingRecipient )
		{
			pgpAssert(
				curUser->location == kPGPRecipientUserLocation_RecipientList );
			
			/* 
			** Missing recipients are never allowed in the user list.
			** Remove from view
			*/
			curUser->location = kPGPRecipientUserLocation_Hidden;
			*numMovedUsers += 1;
		}
		else
		{
			PGPBoolean	moveUser = TRUE;

			if( destinationList == kPGPRecipientUserLocation_RecipientList )
			{
				PGPBoolean	missingARRs = FALSE;
				PGPBoolean	markedARRs 	= FALSE;
				
				if( recipients->arrEnforcement != kPGPARREnforcement_None )
				{
					if( curUser->kind == kPGPRecipientUserKind_Key )
					{
						moveUser = MarkKeyARRsForUserToRecipientMove(
										recipients, curUser->userInfo.key,
										markValue, &markedARRs, &missingARRs );
					}
					else
					{
						pgpAssert( curUser->kind ==
											kPGPRecipientUserKind_Group );

						moveUser = MarkGroupARRsForUserToRecipientMove(
										recipients, curUser,
										markValue, &markedARRs, &missingARRs );
					}
				}

				if( moveUser )
				{
					curUser->markValue 		= markValue;
					curUser->movedManually	= TRUE;
					
					*numMovedUsers += 1;
					
					if( markedARRs )
						*movedARRs = TRUE;
						
					if( missingARRs )
					{
						err = SendUserEvent( recipients,
									kPGPRecipientEvent_MoveUserWarningEvent,
									curUser );
					}
				}
				else
				{
					pgpAssert( ! markedARRs );
					
					err = SendUserEvent( recipients,
									kPGPRecipientEvent_MoveUserFailedEvent,
									curUser );
				}
			}
			else
			{
				if( recipients->arrEnforcement != kPGPARREnforcement_None )
				{
					if( curUser->kind == kPGPRecipientUserKind_Key )
					{
						if( curUser->movedManually )
						{
							MarkKeyARRsForRecipientToUserMove(
										recipients, curUser->userInfo.key,
										markValue );
						}
						else if( curUser->userInfo.enforcedARRRefCount != 0 )
						{
							err = SendUserEvent( recipients,
									kPGPRecipientEvent_MovedARRWarningEvent,
									curUser );
						}
					}
					else
					{
						pgpAssert( curUser->kind ==
											kPGPRecipientUserKind_Group );
					
						MarkGroupARRsForRecipientToUserMove( recipients,
									curUser, markValue );
					}
				}
				
				if( moveUser )
				{
					curUser->markValue 		= markValue;
					curUser->movedManually	= FALSE;

					*numMovedUsers += 1;
				}
			}
		}
		
		if( IsPGPError( err ) )
			break;
	}

	/* Second pass. Move all users with correct mark value */
	curKey = recipients->keys;
	while( IsntNull( curKey ) && IsntPGPError( err ) )
	{
		curUser = curKey->users;
		while( IsntNull( curUser ) )
		{
			if( curUser->markValue == markValue &&
				curUser->location != destinationList )
			{
				curUser->location = destinationList;
				
				err = SendUserEvent( recipients,
							kPGPRecipientEvent_MovedUserEvent, curUser );
				if( IsPGPError( err ) )
					break;
			}
		
			curUser = curUser->nextUser;
		}
		
		curKey = curKey->nextKey;
	}

	curUser = recipients->groups;
	while( IsntNull( curUser ) && IsntPGPError( err ))
	{
		if( curUser->markValue == markValue &&
			curUser->location != destinationList )
		{
			curUser->location = destinationList;
			
			err = SendUserEvent( recipients,
							kPGPRecipientEvent_MovedUserEvent, curUser );
			if( IsPGPError( err ) )
				break;
		}
	
		curUser = curUser->nextUser;
	}
	
	return( err );
}

	static PGPError
pgpAddKeyToSet(
	PGPKeyRef		theKey,
	PGPKeySetRef	keySet,
	PGPBoolean		commitKeySet)
{
	PGPError		err;
	PGPKeySetRef	singletonSet;
	
	err = PGPNewSingletonKeySet( theKey, &singletonSet );
	if( IsntPGPError( err ) )
	{
		err = PGPAddKeys( singletonSet, keySet );
		if( IsntPGPError( err ) && commitKeySet )
		{
			err = PGPCommitKeyRingChanges( keySet );
		}
		
		(void) PGPFreeKeySet( singletonSet );
	}
	
	return( err );
}

	PGPError
PGPGetRecipientKeys(
	PGPRecipientsList	*recipients,
	PGPKeySetRef		*keySetPtr,
	PGPKeySetRef		*newKeysPtr,
	PGPUInt32			*keyListCountPtr,
	PGPRecipientSpec	**keyListPtr)
{
	PGPError			err				= kPGPError_NoErr;
	PGPKeySetRef		keySet			= kInvalidPGPKeySetRef;
	PGPBoolean			haveNewKeys		= FALSE;
	PGPUInt32			keyListCount	= 0;
	PGPRecipientSpec	*keyList		= NULL;
	
	PGPValidatePtr( keySetPtr );
	*keySetPtr	= NULL;
	
	err = PGPNewKeySet( recipients->context, &keySet );
	if( IsntPGPError( err ) )
	{
		PGPRecipientKey		*curKey;
		PGPRecipientUser	*curUser;
		PGPUInt32			markValue;
		
		markValue = GetNextMarkValue();
		
		/* Mark keys in recipient list */
		curKey = recipients->keys;
		while( IsntNull( curKey ) )
		{
			if( curKey->isNewOrChangedKey )
				haveNewKeys = TRUE;
				
			curUser = curKey->users;
			while( IsntNull( curUser ) )
			{
				if( curUser->location ==
							kPGPRecipientUserLocation_RecipientList )
				{
					curKey->markValue = markValue;
					break;
				}
				
				curUser = curUser->nextUser;
			}
		
			curKey = curKey->nextKey;
		}
		
		/* Mark group keys in recipient list */
		curUser = recipients->groups;
		while( IsntNull( curUser ) && IsntPGPError( err ) )
		{
			if( curUser->location == kPGPRecipientUserLocation_RecipientList )
			{
				PGPUInt32		itemIndex;
				
				for( itemIndex = 0; itemIndex < curUser->groupInfo.numKeys;
						++itemIndex )
				{
					PGPGroupItem	item;
					
					err = PGPGetIndGroupItem( recipients->groupSet,
								curUser->groupInfo.groupID, itemIndex, &item );
					if( IsntPGPError( err ) )
					{	
						if( item.userValue != 0 )
						{
							curKey = (PGPRecipientKey *) item.userValue;
							if( curKey->isVisible )
							{
								curKey->markValue = markValue;
							}
						}
					}
					else
					{
						break;
					}
				}
			}
			
			curUser = curUser->nextUser;
		}

		/* If creating a key list, count the marked keys and allocate the
			list */
		if( IsntNull( keyListPtr ) )
		{
			curKey = recipients->keys;
			while( IsntNull( curKey ) )
			{
				if( curKey->markValue == markValue )
				{
					++keyListCount;
				}
			
				curKey = curKey->nextKey;
			}
			
			/* Count missing items as well */
			
			curUser = recipients->missingRecipients;
			while( IsntNull( curUser ) )
			{
				if( curUser->location ==
							kPGPRecipientUserLocation_RecipientList )
				{
					++keyListCount;
				}
				
				curUser = curUser->nextUser;
			}
			
			keyList = (PGPRecipientSpec *) PGPNewData( recipients->memoryMgr, 
								keyListCount * sizeof( PGPRecipientSpec ),
								kPGPMemoryMgrFlags_Clear );
			if( IsNull( keyList ) )
				err = kPGPError_OutOfMemory;
		}
		
		if( IsntPGPError( err ) ) 
		{
			PGPRecipientSpec	*curKeySpec = keyList;
			
			/* Final pass. Add marked keys to result set */
			curKey = recipients->keys;
			while( IsntNull( curKey ) && IsntPGPError( err ) )
			{
				if( curKey->markValue == markValue )
				{
					err = pgpAddKeyToSet( curKey->keyRef, keySet, FALSE );
					if( IsntPGPError( err ) && IsntNull( curKeySpec ) )
					{
						PGPKeyID	keyID;
						
						/*
						** If we're creating a recipient list, we need to get
						** the value of curKey->keyRef as it appears in keySet,
						** _not_ our working set, so we have to search by key ID
						*/
						
						err = PGPGetKeyIDFromKey( curKey->keyRef, &keyID );
						if( IsntPGPError( err ) &&
							IsntPGPError( PGPGetKeyByKeyID( keySet, &keyID,
								curKey->algorithm, &curKeySpec->u.key ) ) )
						{
							curKeySpec->type = kPGPRecipientSpecType_Key;
						
							++curKeySpec;
						}
					}
				}
			
				curKey = curKey->nextKey;
			}

			if( IsntPGPError( err ) && IsntNull( curKeySpec ) )
			{
				curUser = recipients->missingRecipients;
				while( IsntNull( curUser ) )
				{
					if( curUser->location ==
								kPGPRecipientUserLocation_RecipientList )
					{
						curKeySpec->type = curUser->missingUser.type;
						
						if( curUser->missingUser.type ==
									kPGPRecipientSpecType_UserID )
						{
							strcpy( curKeySpec->u.userIDStr,
									PGPGetRecipientUserNamePtr( curUser ) );
						}
						else if( curUser->missingUser.type ==
										kPGPRecipientSpecType_KeyID )
						{
							curKeySpec->u.id.keyID =
									*curUser->missingUser.keyID;
							curKeySpec->u.id.algorithm =
									curUser->missingUser.algorithm;
						}
						else
						{
							pgpDebugMsg( "PGPGetRecipientKeys(): Unknown "
									"missing recipient type" );
						}
						
						++curKeySpec;
					}
					
					curUser = curUser->nextUser;
				}
			}
		}
		
		if( IsntPGPError( err ) )
			err = PGPCommitKeyRingChanges( keySet );
			
		if( IsPGPError( err ) )
		{
			PGPFreeKeySet( keySet );
			keySet = kInvalidPGPKeySetRef;
		}
	}
	
	*keySetPtr 			= keySet;
	
	if( IsntNull( keyListPtr ) )
		*keyListPtr			= keyList;

	if( IsntNull( keyListCountPtr ) )
		*keyListCountPtr	= keyListCount;
	
	if( IsntPGPError( err ) &&
		IsntNull( newKeysPtr ) )
	{
		*newKeysPtr = kInvalidPGPKeySetRef;
		
		if( haveNewKeys )
		{
			err = PGPNewKeySet( recipients->context, &keySet );
			if( IsntPGPError( err ) )
			{
				PGPRecipientKey		*curKey;

				curKey = recipients->keys;
				while( IsntNull( curKey ) && IsntPGPError( err ) )
				{
					if( curKey->isNewOrChangedKey )
					{
						err = pgpAddKeyToSet( curKey->keyRef, keySet, FALSE );
					}
				
					curKey = curKey->nextKey;
				}
				
				if( IsntPGPError( err ) )
					err = PGPCommitKeyRingChanges( keySet );
					
				if( IsPGPError( err ) )
				{
					PGPFreeKeySet( keySet );
					keySet = kInvalidPGPKeySetRef;
				}
			}
			
			*newKeysPtr = keySet;
		}
	}
	
	return( err );
}

	static PGPError
pgpUpdateMissingRecipients(
	void				*hwndParent,
	PGPRecipientsList	*recipients,
	PGPBoolean			*haveNewKeys)
{
	PGPError			err 	= kPGPError_NoErr;
	PGPRecipientUser	*curUser;
	PGPKeySetRef		searchResults;
	PGPContextRef		context;
	
	(void) hwndParent;
	
	context 		= recipients->context;
	*haveNewKeys 	= FALSE;
	
	err = PGPNewKeySet( context, &searchResults );
	if( IsntPGPError( err ) )
	{
		/* Search for missing recipients */
		curUser = recipients->missingRecipients;
		while( IsntNull( curUser ) && IsntPGPError( err ) )
		{
			if( curUser->location == kPGPRecipientUserLocation_RecipientList )
			{
				PGPFilterRef	filter = kInvalidPGPFilterRef;
				
				if( curUser->missingUser.type == kPGPRecipientSpecType_UserID )
				{
					err = PGPNewUserIDStringFilter( context,
								PGPGetRecipientUserNamePtr( curUser ),
								kPGPMatchSubString,
								&filter );
				}
				else if( curUser->missingUser.type ==
								kPGPRecipientSpecType_KeyID )
				{
					err = PGPNewKeyIDFilter( context,
								curUser->missingUser.keyID, &filter );
				}
				else
				{
					pgpDebugMsg( "pgpUpdateMissingRecipients(): Unknown "
							"missing recipient type" );
				}
				
				if( IsntPGPError( err ) &&
					PGPFilterRefIsValid( filter ) )
				{
					PGPKeySetRef	tempSet;
					
					err = PGPSearchKeyServerDialog( context,
							recipients->serverCount, recipients->serverList,
							recipients->tlsContext, FALSE, &tempSet,
							PGPOUIKeyServerSearchFilter( context, filter ),
#if PGP_WIN32
							PGPOUIParentWindowHandle(context, (HWND) hwndParent),
#endif
							PGPOLastOption( context ) );
					if( IsntPGPError( err ) && PGPKeySetRefIsValid( tempSet ) )
					{
						PGPUInt32	numKeys;
						
						err = PGPCountKeys( tempSet, &numKeys );
						if( IsntPGPError( err ) && numKeys > 0 )
						{
							*haveNewKeys = TRUE;
							
							err = PGPAddKeys( tempSet, searchResults );
							if( IsntPGPError( err ) )
							{
								err = PGPCommitKeyRingChanges( searchResults );
							}
						}
						
						PGPFreeKeySet( tempSet );
					}
					
					PGPFreeFilter( filter );
				}
			}
			
			curUser = curUser->nextUser;
		}
		
		/* Search for incomplete groups */
		curUser = recipients->groups;
		while( IsntNull( curUser ) && IsntPGPError( err ) )
		{
			if( curUser->location == kPGPRecipientUserLocation_RecipientList &&
				curUser->groupInfo.numMissingKeys > 0 )
			{
				PGPUInt32		itemIndex;
				
				for( itemIndex = 0; itemIndex < curUser->groupInfo.numKeys;
						++itemIndex )
				{
					PGPGroupItem	item;
					
					err = PGPGetIndGroupItem( recipients->groupSet,
								curUser->groupInfo.groupID, itemIndex, &item );
					if( IsntPGPError( err ) && item.userValue == 0 )
					{
						PGPKeySetRef	tempSet;
							
						err = PGPSearchKeyServerDialog( context,
									recipients->serverCount, 
									recipients->serverList,
									recipients->tlsContext, FALSE, &tempSet,
									PGPOUIKeyServerSearchKeyIDList( context,
										1, &item.u.key.keyID ),
#if PGP_WIN32
									PGPOUIParentWindowHandle(context,
										(HWND) hwndParent),
#endif
									PGPOLastOption( context ) );
						if( IsntPGPError( err ) &&
							PGPKeySetRefIsValid( tempSet ) )
						{
							PGPUInt32	numKeys;
							
							err = PGPCountKeys( tempSet, &numKeys );
							if( IsntPGPError( err ) && numKeys > 0 )
							{
								*haveNewKeys = TRUE;
									
								err = PGPAddKeys( tempSet, searchResults );
								if( IsntPGPError( err ) )
								{
									err = PGPCommitKeyRingChanges(
												searchResults );
								}
							}
							
							PGPFreeKeySet( tempSet );
						}
					}
					
					if( IsPGPError( err ) )
						break;
				}
			}
			
			curUser = curUser->nextUser;
		}
		
		if( IsntPGPError( err ) && *haveNewKeys )
		{
			err = AddNewKeys( recipients, searchResults );
		
			curUser = recipients->missingRecipients;
			while( IsntNull( curUser ) && IsntPGPError( err ) )
			{
				if( UserIsVisible( curUser ) )
				{
					if( curUser->missingUser.type == 
								kPGPRecipientSpecType_UserID )
					{
						PGPUInt32			numMatchedUsers;
						PGPRecipientUser	**matchedUserList;
						
						err = FindUsersFromUserID( recipients,
									PGPGetRecipientUserNamePtr( curUser ),
											FALSE, &numMatchedUsers,
											&matchedUserList );
						if( IsntPGPError( err ) )
						{
							if( numMatchedUsers != 0 )
							{
								PGPBoolean	movedARRs;
								PGPUInt32	numMovedUsers = 0;
								
								err = PGPMoveRecipients( recipients,
										kPGPRecipientUserLocation_RecipientList,
										numMatchedUsers, matchedUserList, 
										&numMovedUsers, &movedARRs );
								if( IsntPGPError( err ) )
								{
									if( numMatchedUsers != 1 )
									{
										PGPUInt32	userIndex;
										
										for( userIndex = 0;
												userIndex < numMatchedUsers;
													++userIndex )
										{
											matchedUserList[userIndex]->
													multipleMatch = TRUE;
										}
									}
									
									curUser->location =
											kPGPRecipientUserLocation_Hidden;
								}
							}
							
							PGPFreeData( matchedUserList );
						}
					}
					else if( curUser->missingUser.type == 
								kPGPRecipientSpecType_KeyID )
					{
						PGPRecipientUser	*matchedUser;
						
						err = FindUserFromKeyID( recipients,
									curUser->missingUser.keyID,
									curUser->missingUser.algorithm,
									&matchedUser );
						if( IsntPGPError( err ) && IsntNull( matchedUser ) )
						{
							PGPBoolean	movedARRs;
							PGPUInt32	numMovedUsers = 0;
							
							err = PGPMoveRecipients( recipients,
									kPGPRecipientUserLocation_RecipientList,
									1, &matchedUser, &numMovedUsers,
									&movedARRs );
							if( IsntPGPError( err ) )
							{
								curUser->location =
										kPGPRecipientUserLocation_Hidden;
							}
						}
					}
					else
					{
						pgpDebugMsg( "Unknown missing recipient type" );
					}
				}
				
				curUser = curUser->nextUser;
			}
		}
		
		PGPFreeKeySet( searchResults );
	}
	
	return( err );
}

	PGPError
PGPUpdateMissingRecipients(
	void				*hwndParent,
	PGPRecipientsList	*recipients,
	PGPBoolean			*haveNewKeys)
{
	PGPError	err = kPGPError_NoErr;
	
	PGPValidatePtr( recipients );
	PGPValidatePtr( haveNewKeys );

	*haveNewKeys = FALSE;
	
	if( IsntNull( recipients->serverList ) &&
		recipients->serverCount != 0 )
	{
		err = pgpUpdateMissingRecipients( hwndParent, recipients, haveNewKeys );
	}
	
	return( err );
}

