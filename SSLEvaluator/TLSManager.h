//
//  TLSManager.h
//  SSLEvaluator
//
//  Created by Daniel Bates on 16/05/2021.
//

#import <Foundation/Foundation.h>
#import "EvaluationResult.h"
#import "openssl/ssl.h"

NS_ASSUME_NONNULL_BEGIN

@interface TLSManager : NSObject

+ (instancetype)sharedInstance;

- (instancetype)init NS_DESIGNATED_INITIALIZER;

- (void)runSSLTestsForDomain:(NSString*)domain withCompletion:(void (^)(struct EvaluationResult result))completionBlock;

@end

NS_ASSUME_NONNULL_END
