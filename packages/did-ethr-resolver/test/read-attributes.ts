import { Keys } from '@ew-did-registry/keys';
import { expect } from 'chai';
import {
  Algorithms,
  DIDAttribute,
  Encoding,
  IAuthentication,
  IServiceEndpoint,
  IUpdateData,
  PubKeyType,
} from '@ew-did-registry/did-resolver-interface';
import { Methods } from '@ew-did-registry/did';
import {
  Operator, signerFromKeys, getProvider, walletPubKey, withProvider, withKey,
} from '../src';

import { deployRegistry } from '../../../tests/init-ganache';

export function readAttributeTestSuite() {
  describe('Read attribute tests', function () {
    this.timeout(0);
    let operator: Operator;
    let did: string;
    let validity: number;
    let keys: Keys;

    beforeEach(async function () {
      ({ operator, validity, keys, did } = this);
    });

    it('readAttribute should read public key by its hex value and type', async () => {
      const attribute = DIDAttribute.PublicKey;
      const k = new Keys();
      const updateData: IUpdateData = {
        algo: Algorithms.Secp256k1,
        type: PubKeyType.VerificationKey2018,
        encoding: Encoding.HEX,
        value: { publicKey: `0x${k.publicKey}`, tag: 'key-1' },
      };
      await operator.update(did, attribute, updateData, validity);
      const publicKeyAttr = await operator.readAttribute(did, { publicKey: { publicKeyHex: updateData.value.publicKey, type: `${updateData.algo}${updateData.type}` } });
      expect(publicKeyAttr.publicKeyHex === updateData.value);
    });

    it('readAttribute should read service endpoint', async () => {
      const attribute = DIDAttribute.ServicePoint;
      const endpoint = 'https://test.readAttribute.com';
      const serviceId = 'UserClaimURL';
      const updateData: IUpdateData = {
        type: attribute,
        value: {
          id: `${did}#service-${serviceId}`,
          type: 'ClaimStore',
          serviceEndpoint: endpoint,
        },
      };
      await operator.update(did, attribute, updateData, validity);
      const serviceEndpointAttr = await operator.readAttribute(did, {
        service: { serviceEndpoint: `${updateData.value.serviceEndpoint}` },
      }) as IServiceEndpoint;
      expect(serviceEndpointAttr.serviceEndpoint === updateData.value);
    });

    it('readAttribute should read delegate by given Ethereum address', async () => {
      const attribute = DIDAttribute.Authenticate;
      const delegate = new Keys();
      const updateData: IUpdateData = {
        algo: Algorithms.ED25519,
        type: PubKeyType.VerificationKey2018,
        encoding: Encoding.HEX,
        delegate: delegate.getAddress(),
      };
      await operator.update(did, attribute, updateData, validity);
      await operator.read(did);
      const delegateAttr = await operator.readAttribute(did, {
        publicKey: {
          ethereumAddress: `${delegate.getAddress()}`,
        },
      }) as IAuthentication;
      expect(delegateAttr.publicKey === updateData.delegate);
    });

    it('resolver should read did owner public key', async () => {
      await operator.create();
      expect((await operator.readOwnerPubKey(did))).equal(keys.publicKey);
    });
  });
}


