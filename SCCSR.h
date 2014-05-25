/*
	This file is part of ios-csr.
	Copyright (C) 2013-14 Ales Teska

	ios-csr is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	ios-csr is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with ios-csr.  If not, see <http://www.gnu.org/licenses/>.
*/

#import <Foundation/Foundation.h>

@interface SCCSR : NSObject

@property (nonatomic, strong) NSString* countryName;
@property (nonatomic, strong) NSString* organizationName;
@property (nonatomic, strong) NSString* organizationalUnitName;
@property (nonatomic, strong) NSString* commonName;

@property (nonatomic, strong) NSData* subjectDER;

-(NSData *) build:(NSData *)publicKeyBits privateKey:(SecKeyRef)privateKey;

@end
