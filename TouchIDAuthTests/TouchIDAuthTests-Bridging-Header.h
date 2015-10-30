//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

#import <TouchIDAuth/TouchIDAuth.h>
#import "A0RSAKeyExporter.h"
#import "NSData+A0JWTSafeBase64.h"
#import "A0TouchID.h"

@interface A0TouchIDAuthentication (Testing)

@property (strong, nonatomic) A0TouchID *touchID;

@end
