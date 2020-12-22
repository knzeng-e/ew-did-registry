/* eslint-disable func-names */
// eslint-disable-next-line import/no-extraneous-dependencies
import { Keys } from '@ew-did-registry/keys';
import {
  IdentityOwner,
} from '@ew-did-registry/did-resolver-interface';
import { Methods } from '@ew-did-registry/did';
import {
  Operator, signerFromKeys, ethrReg, getProvider, walletPubKey, withProvider, withKey,
} from '../src';
import { deployRegistry } from '../../../tests/init-ganache';
import { serviceTestSuite } from './did-operator-services.test';
import { readAttributeTestSuite } from './read-attributes';
import { operatorTestSuite } from './did-operator';

const keys = new Keys({
  privateKey: '3f8118bf3224a722e55eface0c04bc8bbb7a725b3a6e38744fbfed900bbf3e7b',
});
const did = `did:${Methods.Erc1056}:${keys.getAddress()}`;

const validity = 10 * 60 * 1000;
let operator: Operator;
let registry: string;
let owner: IdentityOwner;

describe('[DID-ETHR-RESOLVER PACKAGE]: DID-OPERATOR', function () {
  this.timeout(0);

  beforeEach(async function () {
    registry = await deployRegistry([keys.getAddress()]);
    owner = withKey(withProvider(signerFromKeys(keys), getProvider()), walletPubKey);
    operator = new Operator(
      owner,
      { method: Methods.Erc1056, abi: ethrReg.abi, address: registry },
    );

    await operator.create();

    Object.assign(this, { operator, validity, keys, did, registry });
  });

  operatorTestSuite();
  serviceTestSuite();
  readAttributeTestSuite();
});
