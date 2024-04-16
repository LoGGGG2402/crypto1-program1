"use strict";

/********* External Imports ********/

const {stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes} = require("./lib");
const {init} = require("mocha/lib/cli/commands");
const {subtle} = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Helper Functions ********/
async function generateKey(password, salt) {
    let keyMaterial = await subtle.importKey(
        "raw",
        stringToBuffer(password),
        {name: "PBKDF2"},
        false,
        ["deriveKey"]
    );
    return await subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        {"name": "AES-GCM", "length": 256},
        true,
        ["encrypt", "decrypt"]
    );
}


async function encrypt(data, key, iv) {
    // Encrypt the data using AES-GCM
    const encryptedData = await subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        stringToBuffer(data)
    );

    return encodeBuffer(encryptedData);

}

async function decrypt(data, key, iv) {
    // Decrypt the data using AES-GCM
    const decryptedData = await subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        decodeBuffer(data)
    );

    return bufferToString(decryptedData);

}

/********* Implementation ********/
class Keychain {
    /**
     * Initializes the keychain using the provided information. Note that external
     * users should likely never invoke the constructor directly and instead use
     * either Keychain.init or Keychain.load.
     * Arguments:
     *  You may design the constructor with any parameters you would like.
     * Return Type: void
     */
    constructor() {
        this.data = {
            /* Store member variables that you intend to be public here
               (i.e. information that will not compromise security if an adversary sees) */
        };
        this.secrets = {
            /* Store member variables that you intend to be private here
               (information that an adversary should NOT see). */
            // iv: getRandomBytes(16),
        };

        // throw "Not Implemented!";
    };

    /**
     * Creates an empty keychain with the given password.
     *
     * Arguments:
     *   password: string
     * Return Type: void
     */
    static async init(password) {
        const keychain = new Keychain();
        keychain.kvs = {};
        let salt = getRandomBytes(16);
        let iv = getRandomBytes(16);
        let key = await generateKey(password, salt);
        keychain.secrets = {
            iv: iv,
            key: key,
            encKey: await encrypt(password, key, iv),
            salt: salt,
        };
        return keychain;
    }

    /**
     * Loads the keychain state from the provided representation (repr). The
     * repr variable will contain a JSON encoded serialization of the contents
     * of the KVS (as returned by the dump function). The trustedDataCheck
     * is an *optional* SHA-256 checksum that can be used to validate the
     * integrity of the contents of the KVS. If the checksum is provided and the
     * integrity check fails, an exception should be thrown. You can assume that
     * the representation passed to load is well-formed (i.e., it will be
     * a valid JSON object).Returns a Keychain object that contains the data
     * from repr.
     *
     * Arguments:
     *   password:           string
     *   repr:               string
     *   trustedDataCheck: string
     * Return Type: Keychain
     */
    static async load(password, repr, trustedDataCheck) {
        if (trustedDataCheck) {
            let hash = await subtle.digest('SHA-256', decodeBuffer(repr));
            hash = encodeBuffer(hash);
            if (hash !== trustedDataCheck) {
                throw "Integrity check failed!";
            }
        }

        const keychain = new Keychain();

        const jsonRepr = JSON.parse(repr);

        keychain.kvs = jsonRepr.kvs;
        let iv = decodeBuffer(jsonRepr.secrets.iv); // Decode the iv from a Base64 string
        let salt = decodeBuffer(jsonRepr.secrets.salt);
        let key = await generateKey(password, salt); // Pass the stored salt

        let pass = await decrypt(jsonRepr.secrets.encKey, key, iv);
        if (pass !== password) {
            throw "Integrity check failed!";
        }

        keychain.secrets = {
            iv: iv,
            key: key,
        }
        return keychain;
    };

    /**
     * Returns a JSON serialization of the contents of the keychain that can be
     * loaded back using the load function. The return value should consist of
     * an array of two strings:
     *   arr[0] = JSON encoding of password manager
     *   arr[1] = SHA-256 checksum (as a string)
     * As discussed in the handout, the first element of the array should contain
     * all of the data in the password manager. The second element is a SHA-256
     * checksum computed over the password manager to preserve integrity.
     *
     * Return Type: array
     */
    async dump() {
        const repr = {
            kvs: this.kvs,
            secrets: {
                iv: encodeBuffer(this.secrets.iv),
                encKey: this.secrets.encKey,
                salt: encodeBuffer(this.secrets.salt),
            }
        };

        const hash = await subtle.digest('SHA-256', decodeBuffer(JSON.stringify(repr)));
        return [JSON.stringify(repr), encodeBuffer(hash)];
    };

    /**
     * Fetches the data (as a string) corresponding to the given domain from the KVS.
     * If there is no entry in the KVS that matches the given domain, then return
     * null.
     *
     * Arguments:
     *   name: string
     * Return Type: Promise<string>
     */
    async get(name) {
        const key = await encrypt(name, this.secrets.key, this.secrets.iv);
        if (!this.kvs[key]) {
            return null;
        }
        return await decrypt(this.kvs[key], this.secrets.key, this.secrets.iv);
    };

    /**
     * Inserts the domain and associated data into the KVS. If the domain is
     * already in the password manager, this method should update its value. If
     * not, create a new entry in the password manager.
     *
     * Arguments:
     *   name: string
     *   value: string
     * Return Type: void
     */
    async set(name, value) {
        // name and value should not whitespace only
        if (!name.trim() || !value.trim()) {
            throw "Invalid input!";
        }
        if (value.length > MAX_PASSWORD_LENGTH) {
            throw "Password is too long!";
        }
        const key = await encrypt(name, this.secrets.key, this.secrets.iv);
        this.kvs[key] = await encrypt(value, this.secrets.key, this.secrets.iv);
    };

    /**
     * Removes the record with name from the password manager. Returns true
     * if the record with the specified name is removed, false otherwise.
     *
     * Arguments:
     *   name: string
     * Return Type: Promise<boolean>
     */
    async remove(name) {
        const key = await encrypt(name, this.secrets.key, this.secrets.iv);
        if (this.kvs[key]) {
            delete this.kvs[key];
            return true;
        }
        else {
            return false;
        }
    };
}

module.exports = {Keychain}
