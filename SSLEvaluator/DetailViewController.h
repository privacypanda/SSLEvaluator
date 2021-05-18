//
//  DetailViewController.h
//  SSLEvaluator
//
//  Created by Daniel Bates on 17/05/2021.
//

#import <Cocoa/Cocoa.h>
#import "openssl/x509v3.h"
#import "EvaluationResult.h"

NS_ASSUME_NONNULL_BEGIN

@interface DetailViewController : NSViewController

@property struct EvaluationResult result;
@property (nonatomic, strong) NSString* hostname;

@end

NS_ASSUME_NONNULL_END
