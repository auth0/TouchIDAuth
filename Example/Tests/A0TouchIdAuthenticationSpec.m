// A0TouchIdAuthenticationSpec.m
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

#import "Specta.h"
#import "A0TouchIDAuthentication.h"
#import "A0TouchID.h"

#import <UIKit/UIKit.h>
#import <JWTDecode/A0JWTDecoder.h>

#define HC_SHORTHAND
#import <OCHamcrest/OCHamcrest.h>
#define MOCKITO_SHORTHAND
#import <OCMockito/OCMockito.h>

#define kCustomSubject @"A SUBJECT"
#define kCustomIssuer @"A ISSUER"
#define kCustomValue @"custom_value"

@interface A0TouchIDAuthentication (Testing)
@property (strong, nonatomic) A0TouchID *touchID;

//Not the best way to test it but it's cleaner that handling block stubs
//TODO: Refactor in step objetcs to mock (maybe NSOperation).
- (void)checkKeyPair;
- (void)generateJWT;

@end

SpecBegin(A0TouchIdAuthentication)

describe(@"A0TouchIdAuthentication", ^{

    __block A0TouchIDAuthentication *authentication;
    __block A0TouchID *touchID;

    beforeEach(^{
        authentication = [[A0TouchIDAuthentication alloc] init];
        touchID = mock(A0TouchID.class);
        authentication.touchID = touchID;
        [given(touchID.isAvailable) willReturnBool:YES];
    });

    describe(@"Auth Flow", ^{

        __block NSData *generatedKey;
        __block NSString *signedJWT;
        __block NSDictionary *payload;

        beforeEach(^{
            authentication.registerPublicKey = ^(NSData *pubKey, A0RegisterCompletionBlock completion, A0ErrorBlock errorBlock){
                generatedKey = pubKey;
                completion();
            };
            authentication.authenticate = ^(NSString *jwt, A0ErrorBlock errorBlock){
                signedJWT = jwt;
            };
            generatedKey = nil;
            signedJWT = nil;
        });

        afterEach(^{
            [authentication reset];
        });

        it(@"should fail when no callback is set", ^{
            authentication.registerPublicKey = nil;
            authentication.authenticate = nil;
            expect(^{
                [authentication start];
            }).to.raise(NSInternalInconsistencyException);
        });

        context(@"no TouchID", ^{

            __block NSError *failureReason;

            beforeEach(^{
                authentication.onError = ^(NSError *error) {
                    failureReason = error;
                };
                failureReason = nil;
                [given(touchID.isAvailable) willReturnBool:NO];
                [authentication start];
            });

            it(@"should fail", ^{
                expect(failureReason).notTo.beNil();
            });

            it(@"should have no TouchID error code", ^{
                expect(failureReason.code).to.equal(A0TouchIDAuthenticationErrorTouchIDNotAvailable);
            });

        });

        context(@"TouchID validation", ^{

            __block BOOL failed;

            beforeEach(^{
                authentication.onError = ^(NSError *error) {
                    failed = YES;
                };
                failed = NO;
            });

            it(@"should validate with TouchID", ^{
                [authentication start];
                [MKTVerify(touchID) validateWithCompletion:anything() localizedReason:anything()];
            });

            it(@"should fail when TouchID validation isnt successful", ^{
                MKTArgumentCaptor *captor = [[MKTArgumentCaptor alloc] init];
                [authentication start];
                [MKTVerify(touchID) validateWithCompletion:[captor capture] localizedReason:anything()];
                void (^touchBlock)(BOOL, NSError *) = captor.value;
                touchBlock(NO, nil);
                expect(failed).will.beTruthy();
            });
        });

        context(@"Existing Key Pair", ^{

            beforeAll(^{
                [authentication checkKeyPair];
                generatedKey = nil;
            });

            it(@"should not call register key block", ^{
                [authentication checkKeyPair];
                expect(generatedKey).will.beNil();
            });

        });

        context(@"Generates Key Pair", ^{

            it(@"should call register key block with public key", ^{
                [authentication checkKeyPair];
                expect(generatedKey).willNot.beNil();
            });
            
        });

        sharedExamplesFor(@"valid JWT", ^(NSDictionary *data) {

            it(@"non-nil JWT", ^{
                expect(signedJWT).notTo.beNil();
            });

            it(@"includes sub claim", ^{
                expect(payload[@"sub"]).notTo.beNil();
            });

            it(@"includes iat claim", ^{
                expect(payload[@"iat"]).to.beGreaterThan(0);
            });

            it(@"includes exp claim", ^{
                expect(payload[@"exp"]).to.beGreaterThan(0);
            });

            it(@"exp claim is around 30 seconds from iat", ^{
                NSTimeInterval iat = [payload[@"iat"] doubleValue];
                NSTimeInterval exp = [payload[@"exp"] doubleValue];
                expect(exp - iat).to.beCloseToWithin(30, 0.1);
            });

            it(@"includes device", ^{
                expect(payload[@"device"]).to.equal([[UIDevice currentDevice] name]);
            });
        });

        context(@"JWT default payload", ^{

            beforeEach(^{
                authentication.authenticate = ^(NSString *jwt, A0ErrorBlock errorBlock){
                    signedJWT = jwt;
                    payload = [A0JWTDecoder payloadOfJWT:jwt error:nil];
                };
                payload = nil;
                [authentication checkKeyPair];
            });

            itBehavesLike(@"valid JWT", nil);
        });

        context(@"JWT custom payload", ^{

            __block NSDictionary *payload;

            beforeEach(^{
                authentication.authenticate = ^(NSString *jwt, A0ErrorBlock errorBlock){
                    signedJWT = jwt;
                    payload = [A0JWTDecoder payloadOfJWT:jwt error:nil];
                };
                authentication.jwtPayload = ^{
                    return @{
                             @"sub": kCustomSubject,
                             @"iss": kCustomIssuer,
                             @"custom": kCustomValue,
                             };
                };
                payload = nil;
                [authentication checkKeyPair];
            });

            itBehavesLike(@"valid JWT", nil);

            it(@"overrides sub claim", ^{
                expect(payload[@"sub"]).will.equal(kCustomSubject);
            });

            it(@"includes iss claim", ^{
                expect(payload[@"iss"]).will.equal(kCustomIssuer);
            });

            it(@"includes custom key", ^{
                expect(payload[@"custom"]).will.equal(kCustomValue);
            });

        });

    });
});

SpecEnd
