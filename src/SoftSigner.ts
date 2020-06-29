import { Signer, TezosMessageUtils } from 'conseiljs';

import { CryptoUtils } from './utils/CryptoUtils'

/**
 *  libsodium/ed25519
 */
export class SoftSigner implements Signer {
    readonly _secretKey: Buffer;
    private _key: Buffer | undefined;
    private _lockTimout: number
    private _unlocked: boolean;

    /**
     * 
     * @param secretKey 
     * @param validity 
     */
    constructor(secretKey: Buffer, validity: number = 60) {
        this._secretKey = secretKey;
        this._unlocked = true;
        this._lockTimout = validity;
        if (validity < 0) { //  assume decrypted key provided
            this._key = secretKey;
        }
    }

    /**
     * Signs a 
     * 
     * @param {Buffer} bytes Bytes to sign
     * @param {Buffer} secretKey Secret key
     * @param {string} passphrase
     * @returns {Buffer} Signature
     */
    public async signOperation(bytes: Buffer, passphrase: string = ''): Promise<Buffer> {
        if (!this._unlocked && passphrase !== '') {
            this._key = await CryptoUtils.decryptMessage(this._secretKey, passphrase, new Buffer(0));
            if (this._lockTimout > 0) { setTimeout(() => { this._key = undefined }, this._lockTimout * 1000); }
        }

        return CryptoUtils.signDetached(TezosMessageUtils.simpleHash(bytes, 32), this._key!);
    }

    /**
     * Convenience function that uses Tezos nomenclature to sign arbitrary text.
     * 
     * @param message UTF-8 test
     * @param {string} passphrase
     * @returns {Promise<string>} base58check-encoded signature prefixed with 'edsig'
     */
    public async signText(message: string, passphrase: string = ''): Promise<string> {
        if (!this._unlocked && passphrase !== '') {
            this._key = await CryptoUtils.decryptMessage(this._secretKey, passphrase, new Buffer(0));
            setTimeout(() => { this._key = undefined }, this._lockTimout * 1000);
        }

        const messageSig = await CryptoUtils.signDetached(Buffer.from(message, 'utf8'), this._key!);

        return TezosMessageUtils.readSignatureWithHint(messageSig, 'edsig');
    }
}
