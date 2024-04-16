"use strict";

const {Keychain} = require('../password-manager');
// Instead of:
// const { expect } = require('chai');

// Use dynamic import:
let expect;
(async () => {
    const chai = await import('chai');
    expect = chai.expect;
})();

// Then use expect as usual in your test cases


describe('Keychain', function () {
    describe('init', function () {
        it('should initialize a keychain with the given password', async function () {
            const password = "password123!";
            const keychain = await Keychain.init(password);
            expect(keychain).to.be.instanceOf(Keychain);
        });
    });

    describe('load', function () {
        it('should load a keychain from a valid representation', async function () {
            const password = "password123!";
            const keychain1 = await Keychain.init(password);
            const [repr, checksum] = await keychain1.dump();
            const keychain2 = await Keychain.load(password, repr, checksum);
            expect(keychain2).to.be.an.instanceOf(Keychain);
        });

        it('should throw an error if checksum does not match', async function () {
            const password = "password123!";
            const keychain1 = await Keychain.init(password);
            const [repr, checksum] = await keychain1.dump();
            const alteredChecksum = checksum + 'a';
            expect(async () => await Keychain.load(password, repr, alteredChecksum)).to.throw('Integrity check failed!');
        });

        it('should throw an error if password mismatch', async function () {
            const password1 = "password123!";
            const password2 = "password456!";
            const keychain1 = await Keychain.init(password1);
            const [repr, checksum] = await keychain1.dump();
            expect(async () => await Keychain.load(password2, repr, checksum)).to.throw('Integrity check failed!');
        });
    });

    describe('dump', function () {
        it('should return a JSON representation and checksum of the keychain', async function () {
            const password = "password123!";
            const keychain = await Keychain.init(password);
            const [repr, checksum] = await keychain.dump();
            expect(repr).to.be.a('string');
            expect(checksum).to.be.a('string');
        });
    });

    describe('get', function () {
        it('should return null for non-existent domain', async function () {
            const password = "password123!";
            const keychain = await Keychain.init(password);
            const data = await keychain.get('nonexistent');
            expect(data).to.be.null;
        });

        it('should return value for existing domain', async function () {
            const password = "password123!";
            const keychain = await Keychain.init(password);
            const name = 'example.com';
            const value = 'examplePassword';
            await keychain.set(name, value);
            const data = await keychain.get(name);
            expect(data).to.equal(value);
        });
    });

    describe('set', function () {
        it('should throw an error for empty name or value', async function () {
            const password = "password123!";
            const keychain = await Keychain.init(password);
            expect(async () => await keychain.set('', 'value')).to.throw('Invalid input!');
            expect(async () => await keychain.set('name', '')).to.throw('Invalid input!');
        });

        it('should throw an error for long value', async function () {
            const password = "password123!";
            const keychain = await Keychain.init(password);
            const longValue = 'a'.repeat(65); // Longer than MAX_PASSWORD_LENGTH
            expect(async () => await keychain.set('name', longValue)).to.throw('Password is too long!');
        });
    });

    describe('remove', function () {
        it('should return false for non-existent domain', async function () {
            const password = "password123!";
            const keychain = await Keychain.init(password);
            const result = await keychain.remove('nonexistent');
            expect(result).to.be.false;
        });

        it('should return true for existing domain', async function () {
            const password = "password123!";
            const keychain = await Keychain.init(password);
            const name = 'example.com';
            const value = 'examplePassword';
            await keychain.set(name, value);
            const result = await keychain.remove(name);
            expect(result).to.be.true;
        });
    });
});
