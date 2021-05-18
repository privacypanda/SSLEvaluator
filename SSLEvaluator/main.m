//
//  main.m
//  SSLEvaluator
//
//  Created by Daniel Bates on 13/05/2021.
//

#import <Cocoa/Cocoa.h>
#import "TLSManager.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        /*
         Start TLS Manager shared instance here and stop application execution at the earliest possible
         point if there is a fatal error.
        */
        if ([TLSManager sharedInstance] == nil)
        {
            return EXIT_FAILURE;
        }
    }
    return NSApplicationMain(argc, argv);
}
