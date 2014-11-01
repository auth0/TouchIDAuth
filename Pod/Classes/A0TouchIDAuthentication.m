// A0TouchIDAuthentication.m
//
// Copyright (c) 2014 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "A0TouchIDAuthentication.h"

#import "NSData+A0JWTSafeBase64.h"

#ifdef __IPHONE_8_0
#import <LocalAuthentication/LocalAuthentication.h>
#endif

#import <libextobjc/EXTScope.h>
#import <SimpleKeychain/A0SimpleKeychain+KeyPair.h>
#import <CommonCrypto/CommonDigest.h>

#define kHashLength CC_SHA256_DIGEST_LENGTH

@interface A0TouchIDAuthentication ()
@property (strong, nonatomic) A0SimpleKeychain *keychain;
@end

@implementation A0TouchIDAuthentication

- (instancetype)init {
    if (self) {
        _keychain = [A0SimpleKeychain keychainWithService:@"TouchIDAuthentication"];
    }
    return self;
}

- (void)start {
    NSAssert(self.registerPublicKey != nil && self.authenticate, @"register pubkey and authenticate blocks must be non-nil");
    if ([A0TouchIDAuthentication isTouchIDAuthenticationAvailable]) {
        [self performTouchIDChallenge];
    } else {
        [self safeFailWithError:[self touchIDNotAvailableError]];
    }
}

+ (BOOL)isTouchIDAuthenticationAvailable {
#if TARGET_IPHONE_SIMULATOR
    return YES;
#elif defined __IPHONE_8_0
    if (floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_7_1) { //iOS 8
        LAContext *context = [[LAContext alloc] init];
        NSError *error;
        BOOL available = [context canEvaluatePolicy: LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
        if (!available || error) {
            NSLog(@"TouchID is not available for device. Error: %@", error);
        }
        return available;
    } else { //iOS <= 7.1
        NSLog(@"You need iOS 8 to use TouchID local authentication");
        return NO;
    }
#else
    NSLog(@"You need iOS 8 to use TouchID local authentication");
    return NO;
#endif
}

#pragma mark - Manage Key Pair

- (void)performTouchIDChallenge {
#if TARGET_IPHONE_SIMULATOR
    [self checkKeyPair];
#else
    @weakify(self);
    LAContext *context = [[LAContext alloc] init];
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:NSLocalizedString(nil, nil)
                      reply:^(BOOL success, NSError *error) {
                          @strongify(self);
                          if (success) {
                              [self checkKeyPair];
                          } else {
                              [self safeFailWithError:error];
                          }
    }];
#endif
}

- (void)checkKeyPair {
    @weakify(self);
    A0RegisterCompletionBlock completionBlock = ^{
        @strongify(self);
        [self generateJWT];
    };
    A0ErrorBlock errorBlock = ^(NSError *error) {
        @strongify(self);
        [self safeFailWithError:error];
    };

    NSString *publicTag = [self publicKeyTag];
    NSString *privateTag = [self privateKeyTag];

    if ([self.keychain hasRSAKeyWithTag:publicTag]) {
        completionBlock();
    } else {
        [self.keychain generateRSAKeyPairWithLength:A0SimpleKeychainRSAKeySize1024Bits
                                       publicKeyTag:publicTag
                                      privateKeyTag:privateTag];
        NSData *publicKeyData = [self.keychain dataForRSAKeyWithTag:publicTag];
        if (self.registerPublicKey) {
            self.registerPublicKey(publicKeyData, completionBlock, errorBlock);
        }
    }
}

- (NSString *)publicKeyTag {
    return [[[NSBundle mainBundle] bundleIdentifier] stringByAppendingString:@".pubkey"];
}

- (NSString *)privateKeyTag {
    return [[[NSBundle mainBundle] bundleIdentifier] stringByAppendingString:@".key"];
}

#pragma mark - JWT

- (void)generateJWT {
    @weakify(self);
    A0ErrorBlock errorBlock = ^(NSError *error) {
        @strongify(self);
        [self safeFailWithError:error];
    };
    NSDictionary *header = @{
                             @"alg": @"RS256",
                             @"typ": @"JWT",
                             };
    NSMutableDictionary *claims = [@{
                                     @"device": [[UIDevice currentDevice] name],
                                    } mutableCopy];
    if (self.jwtPayload) {
        [claims addEntriesFromDictionary:self.jwtPayload()];
    }
    NSString *headerBase64 = [[NSJSONSerialization dataWithJSONObject:header options:0 error:nil] a0_jwtSafeBase64String];
    NSString *claimsBase64 = [[NSJSONSerialization dataWithJSONObject:claims options:0 error:nil] a0_jwtSafeBase64String];

    NSString *jwtToSign = [[headerBase64 stringByAppendingString:@"."] stringByAppendingString:claimsBase64];
    NSString *signatureBase64 = [[self signJWT:jwtToSign keyTag:[self privateKeyTag]] a0_jwtSafeBase64String];
    NSString *jwt = [[jwtToSign stringByAppendingString:@"."] stringByAppendingString:signatureBase64];
    if (self.authenticate) {
        self.authenticate(jwt, errorBlock);
    }
}

- (NSData *)signJWT:(NSString *)jwt keyTag:(NSString *)keyTag {
    SecKeyRef privateKeyRef = [self.keychain keyRefOfRSAKeyWithTag:keyTag];
    NSData *signedHash;
    if (privateKeyRef) {
        size_t signatureSize = SecKeyGetBlockSize(privateKeyRef);
        uint8_t *signatureBytes = malloc(signatureSize * sizeof(uint8_t));
        memset(signatureBytes, 0x0, signatureSize);
        NSData *hashedJWT = [self hashValue:jwt];
        OSStatus status = SecKeyRawSign(privateKeyRef, kSecPaddingPKCS1SHA256, [hashedJWT bytes], kHashLength, signatureBytes, &signatureSize);
        if (status == errSecSuccess) {
            signedHash = [NSData dataWithBytes:signatureBytes length:signatureSize];
        }
        CFRelease(privateKeyRef);
        if (signatureBytes) {
            free(signatureBytes);
        }
    }
    return signedHash;
}

- (NSData *)hashValue:(NSString *)value {
    CC_SHA256_CTX ctx;

    uint8_t * hashBytes = malloc(CC_SHA256_DIGEST_LENGTH * sizeof(uint8_t));
    memset(hashBytes, 0x0, CC_SHA256_DIGEST_LENGTH);

    NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];

    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, [valueData bytes], (CC_LONG)[valueData length]);
    CC_SHA256_Final(hashBytes, &ctx);

    NSData *hash = [NSData dataWithBytes:hashBytes length:CC_SHA256_DIGEST_LENGTH];

    if (hashBytes) {
        free(hashBytes);
    }

    return hash;
}

#pragma mark - Error methods

- (NSError *)touchIDNotAvailableError {
    NSError *error = [[NSError alloc] initWithDomain:@"com.auth0.TouchIDAuthentication"
                                                code:A0TouchIDAuthenticationErrorTouchIDNotAvailable
                                            userInfo:@{
                                                       NSLocalizedDescriptionKey: NSLocalizedString(@"TouchID is not configured or supported in the device", @"TouchID not available"),
                                                       }];
    return error;
}

- (void)safeFailWithError:(NSError *)error {
    if (self.onError) {
        self.onError(error);
    }
}
@end
