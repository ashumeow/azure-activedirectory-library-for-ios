// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.
#import <Foundation/Foundation.h>

@class ADAuthenticationError;
/*! Contains the details about a user that had authorized resource usage*/
@interface ADUserInformation : NSObject<NSCopying, NSSecureCoding>
{
// OSX Universal Compatibility
@private
    NSString *_userId;
    NSString *_rawIdToken;
    NSDictionary *_allClaims;

    
    BOOL      _userIdDisplayable;
}

/*! Factory method. The default initializer will throw unrecognized selector
 exception. Please use this one instead */
+(ADUserInformation*) userInformationWithUserId: (NSString*) userId
                                          error: (ADAuthenticationError* __autoreleasing*) error;

/*! Factory method to extract user information from the AAD id_token parameter.
 @param: idToken: The contents of the id_token parameter, as passed by the server. */
+(ADUserInformation*) userInformationWithIdToken: (NSString*) idToken
                                           error: (ADAuthenticationError* __autoreleasing*) error;

/* This is the only readonly property, as it is used in the key generation for the cache.
 A new user information object should be created if userId changes */
@property (retain, readonly) NSString* userId;

/*! Determines whether userId is displayable */
@property (readonly) BOOL userIdDisplayable;

/*! May be null */
@property (retain, atomic, readonly, getter = getGivenName) NSString* givenName;

/*! May be null */
@property (retain, atomic, readonly, getter = getFamilyName) NSString* familyName;

/*! May be null */
@property (retain, atomic, readonly, getter = getIdentityProvider) NSString* identityProvider;

/*! May be null */
@property (retain, atomic, readonly, getter = getEMail) NSString* eMail;

/*! May be null */
@property (retain, atomic, readonly, getter = getUniqueName) NSString* uniqueName;

/*! May be null */
@property (retain, atomic, readonly, getter = getUpn) NSString* upn;

/*! Internal representation for guest users to the tenants. May be null. */
@property (retain, atomic, readonly, getter = getTenantId) NSString* tenantId;

@property (retain, atomic, readonly, getter = getSubject) NSString* subject;

/*! Unique object id that identifies the user. Internal user representation. May be null.*/
@property (retain, atomic, readonly, getter = getUserObjectId) NSString* userObjectId;

@property (retain, atomic, readonly, getter = getGuestId) NSString* guestId;

/* A helper method to normalize userId, e.g. remove white spaces, lowercase.*/
+(NSString*) normalizeUserId: (NSString*) userId;

/*! The raw id_token claim string. */
@property (retain, atomic, readonly) NSString* rawIdToken;

/*! Contains all claims that had been read from the id_token. May be null, if the object was not created from a real id_token. */
@property (retain, atomic, readonly) NSDictionary* allClaims;

@end
