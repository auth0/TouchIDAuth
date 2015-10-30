// A0RSAKeyExporterSpec.swift
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

class A0RSAKeyExporterSpec: QuickSpec {
    override func spec() {

        var exporter: A0RSAKeyExporter!

        beforeEach {
            exporter = A0RSAKeyExporter()
        }

        describe("export public key") {
            var value: String!

            beforeEach {
                let data = NSUUID().UUIDString.dataUsingEncoding(NSUTF8StringEncoding)!
                value = String(data: exporter.exportPublicKey(data)!, encoding: NSUTF8StringEncoding)
            }

            it("should contain header") {
                expect(value).to(beginWith("-----BEGIN RSA PUBLIC KEY-----"))
            }

            it("should contain footer") {
                expect(value).to(endWith("-----END RSA PUBLIC KEY-----"))
            }

            it("should have 3 parts") {
                expect(value.componentsSeparatedByString("\n")).to(haveCount(3))
            }

            it("should have key in base64 with max length of 64") {
                let base64Key = value.componentsSeparatedByString("\n").first!
                expect(1...64 ~= base64Key.characters.count).to(beTrue())
            }
        }
    }
}