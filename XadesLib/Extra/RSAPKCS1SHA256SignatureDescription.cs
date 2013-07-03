using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IM.Xades.Extra
{
    public sealed class RSAPKCS1SHA256SignatureDescription : SignatureDescription
    {
        public RSAPKCS1SHA256SignatureDescription()
        {
            this.KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            this.DigestAlgorithm = typeof(SHA256Managed).FullName;
            this.FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
            this.DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            RSAPKCS1SignatureDeformatter signatureDeformatter = new RSAPKCS1SignatureDeformatter(key);
            signatureDeformatter.SetHashAlgorithm("SHA256");
            return (AsymmetricSignatureDeformatter)signatureDeformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            RSAPKCS1SignatureFormatter signatureFormatter = new RSAPKCS1SignatureFormatter(key);
            signatureFormatter.SetHashAlgorithm("SHA256");
            return (AsymmetricSignatureFormatter)signatureFormatter;
        }
    }
}
