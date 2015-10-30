// A0JWTSafeBase64Spec.swift
//
// Copyright (c) 2015 Auth0 (http://auth0.com)
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

import Quick
import Nimble
import Security

func randomDataOfSize(size: Int) -> NSData {
    let data = NSMutableData(length: size)!
    SecRandomCopyBytes(kSecRandomDefault, size, UnsafeMutablePointer<UInt8>(data.mutableBytes))
    return data
}

class A0JWTSafeBase64Spec: QuickSpec {
    override func spec() {

        var base64: String!

        beforeEach {
            let size = Int(arc4random_uniform(400) + 200)
            base64 = randomDataOfSize(size).a0_jwtSafeBase64String()
        }

        it("should not include invalid characters") {
            let urlSafeBase64Set = NSCharacterSet.alphanumericCharacterSet().mutableCopy()
            urlSafeBase64Set.formIntersectionWithCharacterSet(NSCharacterSet.nonBaseCharacterSet().invertedSet)
            urlSafeBase64Set.addCharactersInString("-_")
            let set = urlSafeBase64Set.invertedSet
            expect(base64.rangeOfCharacterFromSet(set)).to(beNil())
        }

        it("should not include '='") {
            expect(base64).notTo(contain("="))
        }

        it("should not include '/'") {
            expect(base64).notTo(contain("/"))
        }

        it("should not include '+'") {
            expect(base64).notTo(contain("+"))
        }

    }
}