/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable func-names */
import chai, { expect } from 'chai';
import equalInAnyOrder from 'deep-equal-in-any-order';
import { BigNumber } from 'ethers/utils';
import { DIDAttribute } from '@ew-did-registry/did-resolver-interface';
import { Operator, documentFromLogs } from '../src';

chai.use(equalInAnyOrder);

export function serviceTestSuite() {
  describe('Service tests', () => {
    const type = DIDAttribute.ServicePoint;
    let operator: Operator;
    let did: string;
    let validity: number;

    beforeEach(async function () {
      ({ operator, did, validity } = this);
      await operator.deactivate(did);
      await operator.create();
    });

    it('service endpoint update should add an entry in service section of the DID document', async () => {
      const endpoint = 'https://test.algo.com';
      const value = {
        id: `${did}#service-${1}`,
        type: 'ClaimStore',
        serviceEndpoint: endpoint,
      };

      await operator.update(did, DIDAttribute.ServicePoint, { type, value }, validity);
      const document = await operator.read(did);

      expect(document.id).equal(did);
      expect(document.service.find(
        ({ serviceEndpoint }) => serviceEndpoint === endpoint,
      )).not.undefined;
    });

    it('should be possible to add two services', async () => {
      let value = {
        id: `${did}#service-${1}`,
        type: 'ClaimStore',
        serviceEndpoint: 'http://servic1.com',
      };

      await operator.update(did, DIDAttribute.ServicePoint, { type, value }, validity);
      const log1 = await operator.readFromBlock(did, new BigNumber(0));

      value = {
        id: `${did}#service-${2}`,
        type: 'ClaimStore',
        serviceEndpoint: 'http://servic2.com',
      };
      const block = await operator.update(did, DIDAttribute.ServicePoint, { type, value }, validity);
      const log2 = await operator.readFromBlock(did, block);

      const document = await operator.read(did);
      expect(document).be.deep.equalInAnyOrder(documentFromLogs(did, [log1, log2]));
      expect(document.service.length).eq(2);
    });

    it('deactivation of the document should revoke services', async () => {
      expect((await operator.read(did)).service.length).equal(0);

      let value = {
        id: `${did}#service-${1}`,
        type: 'ClaimStore',
        serviceEndpoint: 'http://servic1.com',
      };

      await operator.update(did, DIDAttribute.ServicePoint, { type, value }, validity);
      value = {
        id: `${did}#service-${2}`,
        type: 'ClaimStore',
        serviceEndpoint: 'http://servic2.com',
      };
      await operator.update(did, DIDAttribute.ServicePoint, { type, value }, validity);
      expect((await operator.read(did)).service.length).equal(2);

      await operator.deactivate(did);

      expect((await operator.read(did)).service.length).equal(0);
    });
  });
}
