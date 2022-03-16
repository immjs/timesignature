import verify from './node.js';
import { expect } from 'chai';

describe('Time Signature Verification', () => {
  it('should verify a valid signature', async () => {
    const str = 'Hello world! This is the first text to ever be time-signatured!';
    const signature = 'ts.immjs.dev|fP6qNCyG77jqLm7cZ1r+aEmcGfuQn/2gA4s2IIXibvKo1VJIUR47V5MLYFyRYAzqEcNvjI97Vmww6EWb6UgPysa9YeTKvCJYnHAKsVBmmFPkkOHrYP+9jI4CMhwKrMq9A8VZ8QZ3ientrXQScQlQgqm5/IG3TTWDnSo0hGhfYtlr50b5FykVQ5JJ2iVRGZrvd/gXZqY9ijbMtWkk/VgCtNvsWqEbBhOPTs1CYls6e3EF5+kkJUwMSoGZAy8/ntFr+gUR9U2WQytzCAqrGb7ahmHpMt2hnR8NL7bDugPTcWXzH7shjax7skzMAB6uWg1xHlTvo+EHEO13cCH/YSPeig==';

    const [isValid, decrypted] = await verify(str, signature);
    expect(isValid).to.be.true;
  });
  it('should not verify an unmatching signature', async () => {
    const str = 'Nope';
    const signature = 'ts.immjs.dev|WPjBiDFO8FRhFwkxlFW+nF9hw6sQu2XS2OW10XXq2lNq/EH6LhUo+SO7fzMBEqG6rS16vWiD8OKHLslH06UxV8IscoTRW4U1dlrEfimVWFHRTVxhWu7CeO9dx1WVmwBtVg3NdktZBBsLZEYNWk75owfEIVAc+xgTsMEM6UXwAsC5PXD4VcZq3LzkiqSwmFhka+k5BkTp82QKKzL149ZDtx1X5hbxpvbubqr33arwq3cJSFrunHHUZJ79pjOVw25HPpOMCOutf2gruAZF72LJrWZhzeXIBwQKuH7yECBsibQfSo8x3Y8ccxjue+rGKn2PuRwjw7Joobf2W5zIiEwrTQ==';

    const [isValid, decrypted] = await verify(str, signature);
    expect(isValid).to.be.false;
  });
  it('should not verify a signature that has an invalid host', async () => {
    const str = 'Hello world! This is the first text to ever be time-signatured!';
    const signature = 'i.am.malicio.us|WPjBiDFO8FRhFwkxlFW+nF9hw6sQu2XS2OW10XXq2lNq/EH6LhUo+SO7fzMBEqG6rS16vWiD8OKHLslH06UxV8IscoTRW4U1dlrEfimVWFHRTVxhWu7CeO9dx1WVmwBtVg3NdktZBBsLZEYNWk75owfEIVAc+xgTsMEM6UXwAsC5PXD4VcZq3LzkiqSwmFhka+k5BkTp82QKKzL149ZDtx1X5hbxpvbubqr33arwq3cJSFrunHHUZJ79pjOVw25HPpOMCOutf2gruAZF72LJrWZhzeXIBwQKuH7yECBsibQfSo8x3Y8ccxjue+rGKn2PuRwjw7Joobf2W5zIiEwrTQ==';

    const [isValid, decrypted] = await verify(str, signature);
    expect(isValid).to.be.false;
  });
});
