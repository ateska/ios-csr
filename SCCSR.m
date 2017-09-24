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

#import "SCCSR.h"
#include <CommonCrypto/CommonDigest.h>

/*

Certification Request Syntax Specification: http://www.ietf.org/rfc/rfc2986.txt

*/

// Use e.g., https://misc.daniel-marschall.de/asn.1/oid-converter/online.php to convert OID (OBJECT IDENTIFIER) to ASN.1 DER hex forms
static uint8_t OBJECT_commonName[5] = {0x06, 0x03, 0x55, 0x04, 0x03};
static uint8_t OBJECT_countryName[5] = {0x06, 0x03, 0x55, 0x04, 0x06};
static uint8_t OBJECT_organizationName[5] = {0x06, 0x03, 0x55, 0x04, 0x0A};
static uint8_t OBJECT_organizationalUnitName[5] = {0x06, 0x03, 0x55, 0x04, 0x0B};

static uint8_t OBJECT_rsaEncryptionNULL[13] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};

// See: http://oid-info.com/get/1.2.840.113549.1.1.5
static uint8_t SEQUENCE_OBJECT_sha1WithRSAEncryption[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 5, 0x05, 0x00};

static uint8_t SEQUENCE_tag = 0x30;
static uint8_t SET_tag = 0x31;

///

@implementation SCCSR

@synthesize countryName;
@synthesize organizationName;
@synthesize organizationalUnitName;
@synthesize commonName;
@synthesize subjectDER;

-(SCCSR *)init
{
	self = [super init];
	if (!self) return self;

	countryName = nil;
	organizationName = nil;
	organizationalUnitName = nil;
	commonName = nil;

	subjectDER = nil;
	
	return self;
}

-(NSData *) build:(NSData *)publicKeyBits privateKey:(SecKeyRef)privateKey
{
	NSMutableData * CertificationRequestInfo = [self buildCertificationRequestInfo:publicKeyBits];

	// Build signature - step 1: SHA1 hash
	CC_SHA1_CTX SHA1;
	CC_SHA1_Init(&SHA1);
	CC_SHA1_Update(&SHA1, [CertificationRequestInfo mutableBytes], (unsigned int)[CertificationRequestInfo length]);
	unsigned char digest[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1_Final(digest, &SHA1);
	
	// Build signature - step 2: Sign hash
	uint8_t signature[256];
	size_t signature_len = sizeof(signature);
	OSStatus osrc = SecKeyRawSign(
		privateKey,
		kSecPaddingPKCS1SHA1,
		digest, sizeof(digest),
		signature, &signature_len
	);
	assert(osrc == noErr);
	
	NSMutableData * CertificationRequest = [[NSMutableData alloc] initWithCapacity:1024];
	[CertificationRequest appendData:CertificationRequestInfo];
	[CertificationRequest appendBytes:SEQUENCE_OBJECT_sha1WithRSAEncryption length:sizeof(SEQUENCE_OBJECT_sha1WithRSAEncryption)];

	NSMutableData * signdata = [NSMutableData dataWithCapacity:257];
	uint8_t zero = 0;
	[signdata appendBytes:&zero length:1]; // Prepend zero
	[signdata appendBytes:signature length:signature_len];
	[SCCSR appendBITSTRING:signdata into:CertificationRequest];

	[SCCSR enclose:CertificationRequest by:SEQUENCE_tag]; // Enclose into SEQUENCE

	return CertificationRequest;
}


-(NSMutableData *)buildCertificationRequestInfo:(NSData *)publicKeyBits
{
	NSMutableData * CertificationRequestInfo = [[NSMutableData alloc] initWithCapacity:512];
	
	// Add version
	uint8_t version[3] = {0x02, 0x01, 0x00}; // ASN.1 Representation of integer with value 1
	[CertificationRequestInfo appendBytes:version length:sizeof(version)];
	
	
	// Add subject
	NSMutableData * Subject = [[NSMutableData alloc] initWithCapacity:256];
	if (countryName != nil) [SCCSR appendSubjectItem:OBJECT_countryName value:countryName into:Subject];
	if (organizationName != nil) [SCCSR appendSubjectItem:OBJECT_organizationName value:organizationName into:Subject];
	if (organizationalUnitName != nil) [SCCSR appendSubjectItem:OBJECT_organizationalUnitName value:organizationalUnitName into:Subject];
	if (commonName != nil) [SCCSR appendSubjectItem:OBJECT_commonName value:commonName into:Subject];
	[SCCSR enclose:Subject by:SEQUENCE_tag]; // Enclose into SEQUENCE

	subjectDER = [NSData dataWithData:Subject];
	
	[CertificationRequestInfo appendData:Subject];
	
	
	//Add public key info
	NSData * publicKeyInfo = [SCCSR buildPublicKeyInfo:publicKeyBits];
	[CertificationRequestInfo appendData:publicKeyInfo];
	
	// Add attributes
	uint8_t attributes[2] = {0xA0, 0x00};
	[CertificationRequestInfo appendBytes:attributes length:sizeof(attributes)];

	
	[SCCSR enclose:CertificationRequestInfo by:SEQUENCE_tag]; // Enclose into SEQUENCE
	
	return CertificationRequestInfo;
}

/// Utility class methods ...
+(NSData *)buildPublicKeyInfo:(NSData *)publicKeyBits
{
	NSMutableData * publicKeyInfo = [[NSMutableData alloc] initWithCapacity:390];

	[publicKeyInfo appendBytes:OBJECT_rsaEncryptionNULL length:sizeof(OBJECT_rsaEncryptionNULL)];
	[SCCSR enclose:publicKeyInfo by:SEQUENCE_tag]; // Enclose into SEQUENCE
	
	NSMutableData * publicKeyASN = [[NSMutableData alloc] initWithCapacity:260];
	
	NSData * mod = [SCCSR getPublicKeyMod:publicKeyBits];
	char Integer = 0x02; // Integer
	[publicKeyASN appendBytes:&Integer length:1];
	[SCCSR appendDERLength:[mod length] into:publicKeyASN];
	[publicKeyASN appendData:mod];

	NSData * exp = [SCCSR getPublicKeyExp:publicKeyBits];
	[publicKeyASN appendBytes:&Integer length:1];
	[SCCSR appendDERLength:[exp length] into:publicKeyASN];
	[publicKeyASN appendData:exp];

	[SCCSR enclose:publicKeyASN by:SEQUENCE_tag]; // Enclose into ??
	[SCCSR prependByte:0x00 into:publicKeyASN]; // Prepend 0 (?)
	
	[SCCSR appendBITSTRING:publicKeyASN into:publicKeyInfo];
	
	[SCCSR enclose:publicKeyInfo by:SEQUENCE_tag]; // Enclose into SEQUENCE
	
	return publicKeyInfo;
}

+(void)appendSubjectItem:(const uint8_t[5])what value:(NSString *)value into:(NSMutableData *)into
{
	NSMutableData * SubjectItem = [[NSMutableData alloc] initWithCapacity:128];
	[SubjectItem appendBytes:what length:5];
	[SCCSR appendUTF8String:value into:SubjectItem];
	[SCCSR enclose:SubjectItem by:SEQUENCE_tag]; // Enclose into SEQUENCE
	[SCCSR enclose:SubjectItem by:SET_tag]; // Enclose into SET
	
	[into appendData:SubjectItem];
}

+(void)appendUTF8String:(NSString *)string into:(NSMutableData *)into
{
	char strtype = 0x0C; //UTF8STRING
	[into appendBytes:&strtype length:1];
	[SCCSR appendDERLength:[string lengthOfBytesUsingEncoding:NSUTF8StringEncoding] into:into];
	[into appendData:[string dataUsingEncoding:NSUTF8StringEncoding]];
}

+(void)appendDERLength:(size_t)length into:(NSMutableData *)into
{
	assert(length < 0x8000);
	
	if (length < 128)
	{
		uint8_t d = length;
		[into appendBytes:&d length:1];
	}
	else if (length < 0x100)
	{
		uint8_t d[2] = {0x81, length & 0xFF};
		[into appendBytes:&d length:2];
	}
	else if (length < 0x8000)
	{
		uint8_t d[3] = {0x82, (length & 0xFF00) >> 8, length & 0xFF};
		[into appendBytes:&d length:3];
	}
}

+(void)appendBITSTRING:(NSData *)data into:(NSMutableData *)into
{
	char strtype = 0x03; //BIT STRING
	[into appendBytes:&strtype length:1];
	[SCCSR appendDERLength:[data length] into:into];
	[into appendData:data];
}


+(void)enclose:(NSMutableData *)data by:(uint8_t)by
{
	NSMutableData* newdata = [[NSMutableData alloc]initWithCapacity:[data length]+4];
	
	[newdata appendBytes:&by length:1];
	[SCCSR appendDERLength:[data length] into:newdata];
	[newdata appendData:data];
	
	[data setData:newdata];
}

+(void)prependByte:(uint8_t)byte into:(NSMutableData *)into
{
	NSMutableData* newdata = [[NSMutableData alloc]initWithCapacity:[into length]+1];
	
	[newdata appendBytes:&byte length:1];
	[newdata appendData:into];
	
	[into setData:newdata];
}

///

// From http://stackoverflow.com/questions/3840005/how-to-find-out-the-modulus-and-exponent-of-rsa-public-key-on-iphone-objective-c

+ (NSData *)getPublicKeyExp:(NSData *)publicKeyBits
{
	int iterator = 0;
	
	iterator++; // TYPE - bit stream - mod + exp
	[SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator]; // Total size
	
	iterator++; // TYPE - bit stream mod
	int mod_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
	iterator += mod_size;
	
	iterator++; // TYPE - bit stream exp
	int exp_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
	
	return [publicKeyBits subdataWithRange:NSMakeRange(iterator, exp_size)];
}

+(NSData *)getPublicKeyMod:(NSData *)publicKeyBits
{
	int iterator = 0;
	
	iterator++; // TYPE - bit stream - mod + exp
	[SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator]; // Total size
	
	iterator++; // TYPE - bit stream mod
	int mod_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
	
	return [publicKeyBits subdataWithRange:NSMakeRange(iterator, mod_size)];
}

+(int)derEncodingGetSizeFrom:(NSData*)buf at:(int*)iterator
{
	const uint8_t* data = [buf bytes];
	int itr = *iterator;
	int num_bytes = 1;
	int ret = 0;
	
	if (data[itr] > 0x80) {
		num_bytes = data[itr] - 0x80;
		itr++;
	}
	
	for (int i = 0 ; i < num_bytes; i++) ret = (ret * 0x100) + data[itr + i];
	
	*iterator = itr + num_bytes;
	return ret;
}

@end

