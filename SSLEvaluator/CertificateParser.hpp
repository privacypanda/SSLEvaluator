//
//  CertificateParser.h
//  SSLEvaluator
//
//  Created by Daniel Bates on 16/05/2021.
//

#import <Foundation/Foundation.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/evp.h"


NS_ASSUME_NONNULL_BEGIN

@interface CertificateParser : NSObject

@property (assign) X509* cert;

-(instancetype)initWithCertificate:(X509 *)certificate;

-(int)getX509VersionNumber;
-(NSString*) getSerial;
-(NSString *)getCommonName;
-(NSString*)getThumbprint;
-(NSString *)getIssuer;
-(NSMutableArray*) getSubjectAltNames;
-(NSString*)getValidFrom;
-(NSString*)getValidTo;
-(NSMutableArray*) getOcspURLs;
-(NSMutableArray*) getCrlUrls;



@end

NS_ASSUME_NONNULL_END
