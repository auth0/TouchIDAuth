// NSDataBase64Spec.m
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
#import "NSData+A0JWTSafeBase64.h"
#import <UIKit/UIKit.h>

SpecBegin(NSData)

describe(@"A0JWTSafeBase64", ^{

    __block NSString *base64;

    beforeEach(^{
        int size = 400;
        NSMutableData* data = [NSMutableData dataWithCapacity:size];
        for(unsigned int i = 0 ; i < size/4 ; ++i) {
            u_int32_t randomBits = arc4random();
            [data appendBytes:(void*)&randomBits length:4];
        }
        base64 = [data a0_jwtSafeBase64String];
    });

    it(@"should not include '='", ^{
        expect(base64).notTo.contain(@"=");
    });

    it(@"should not include '/'", ^{
        expect(base64).notTo.contain(@"/");
    });

    it(@"should not include '+'", ^{
        expect(base64).notTo.contain(@"+");
    });

});

SpecEnd
