"use strict";

let expect = require('expect.js');
const {Keychain} = require('../password-manager');

function expectReject(promise) {
    return promise.then(
        (result) => expect().fail(`Expected failure, but function returned ${result}`),
        (error) => {
        },
    );
}

describe('Password manager', async function () {
    this.timeout(5000);
    let password = "password123!";

    let kvs = {
        "service1": "value1",
        "service2": "value2",
        "service3": "value3"
    };

    describe('functionality', async function () {

        it('inits without an error', async function () {
            await Keychain.init(password);
        });

        it('can set and retrieve a password', async function () {
            let keychain = await Keychain.init(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            await keychain.set(url, pw);
            expect(await keychain.get(url)).to.equal(pw);
        });

        it('can set and retrieve multiple passwords', async function () {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            for (let k in kvs) {
                expect(await keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('returns null for non-existent passwords', async function () {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.get('www.stanford.edu')).to.be(null);
        });

        it('can remove a password', async function () {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('service1')).to.be(true);
            expect(await keychain.get('service1')).to.be(null);
        });

        it('returns false if there is no password for the domain being removed', async function () {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('www.stanford.edu')).to.be(false);
        });

        it('can dump and restore the database', async function () {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let checksum = data[1];
            let newKeychain = await Keychain.load(password, contents, checksum);

            // Make sure it's valid JSON
            expect(async function () {
                JSON.parse(contents)
            }).not.to.throwException();
            for (let k in kvs) {
                expect(await newKeychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('fails to restore the database if checksum is wrong', async function () {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let fakeChecksum = '3GB6WSm+j+jl8pm4Vo9b9CkO2tZJzChu34VeitrwxXM=';
            await expectReject(Keychain.load(password, contents, fakeChecksum));
        });

        it('returns false if trying to load with an incorrect password', async function () {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let checksum = data[1];
            await expectReject(Keychain.load("fakepassword", contents, checksum));
        });
    });

    describe('security', async function () {

        // Very basic test to make sure you're not doing the most naive thing
        it("doesn't store domain names and passwords in the clear", async function () {
            let keychain = await Keychain.init(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            await keychain.set(url, pw);
            let data = await keychain.dump();
            let contents = data[0];
            expect(contents).not.to.contain(password);
            expect(contents).not.to.contain(url);
            expect(contents).not.to.contain(pw);
        });

        // This test won't be graded directly -- it just exists to make sure your
        // dump include a kvs object with all your urls and passwords, because
        // we will be using that in other tests.
        it('includes a kvs object in the serialized dump', async function () {
            let keychain = await Keychain.init(password);
            for (let i = 0; i < 10; i++) {
                await keychain.set(String(i), String(i));
            }
            let data = await keychain.dump();
            let contents = data[0];
            let contentsObj = JSON.parse(contents);
            expect(contentsObj).to.have.key('kvs');
            expect(contentsObj.kvs).to.be.an('object');
            expect(Object.getOwnPropertyNames(contentsObj.kvs)).to.have.length(10);
        });

        it('should update an entry and not create a new one', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.example.com';
            let pw1 = 'password1';
            let pw2 = 'password2';
            await keychain.set(url, pw1);
            await keychain.set(url, pw2);
            expect(await keychain.get(url)).to.equal(pw2);
        });

        it('should update an entry and not create a new one', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.example.com';
            let pw1 = 'password1';
            let pw2 = 'password2';
            await keychain.set(url, pw1);
            await keychain.set(url, pw2);
            expect(await keychain.get(url)).to.equal(pw2);
        });

        it('should not contain password in the dump', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.example.com';
            let pw = 'password';
            await keychain.set(url, pw);
            let data = await keychain.dump();
            let contents = data[0];
            expect(contents).not.to.contain(password);
        });

        it('should not contain password in the dump', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.example.com';
            let pw = 'password';
            await keychain.set(url, pw);
            let data = await keychain.dump();
            let contents = data[0];
            expect(contents).not.to.contain(password);
        });

        it('should prevent rollback attacks', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.google.com';
            let pw1 = 'oldGooglePassword';
            let pw2 = 'newGooglePassword';
            await keychain.set(url, pw1);
            let data1 = await keychain.dump();
            await keychain.set(url, pw2);
            let data2 = await keychain.dump();
            await expectReject(Keychain.load(password, data1[0], data2[1]));
        });


        it('should not allow setting an empty password', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.example.com';
            let pw = '';
            await expectReject(keychain.set(url, pw));
        });

        it('should not allow setting a password for an empty domain', async function() {
            let keychain = await Keychain.init(password);
            let url = '';
            let pw = 'password';
            await expectReject(keychain.set(url, pw));
        });

        it('should not allow setting a null password', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.example.com';
            let pw = null;
            await expectReject(keychain.set(url, pw));
        });

        it('should not allow setting a password for a null domain', async function() {
            let keychain = await Keychain.init(password);
            let url = null;
            let pw = 'password';
            await expectReject(keychain.set(url, pw));
        });

        it('should not allow setting a password with whitespace only', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.example.com';
            let pw = '     ';
            await expectReject(keychain.set(url, pw));
        });

        it('should not allow setting a password for a domain with whitespace only', async function() {
            let keychain = await Keychain.init(password);
            let url = '     ';
            let pw = 'password';
            await expectReject(keychain.set(url, pw));
        });



    });
});