/*
 *  This file is part of Xades Lib.
 *  Copyright (C) 2012 I.M. vzw
 *
 *  Xades Lib is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  Foobar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with Xades Lib.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Security.Cryptography;
using Security.Cryptography;
using IM.Xades.Internal;
using IM.Xades.Extra;
using System.Security.Cryptography.Xml;
using System.Collections;
using System.Globalization;
using System.IO;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509.Store;

namespace IM.Xades
{
    /// <summary>
    /// Verify XAdES compliant signatures.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Targets the XAdES 1.4.1 standard.  Currently supports Xades-BES and Xades-T.  Other profiles may be added in the future.
    /// </para>
    /// </remarks>
    public class XadesVerifier
    {
        static XadesVerifier()
        {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            CryptoConfig.AddAlgorithm(typeof(OptionalDeflateTransform), OptionalDeflateTransform.AlgorithmUri);
        }

        private XmlNamespaceManager nsMgr;

        private TimeSpan timestampGracePeriod;

        private X509Certificate2 trustedTsaCert;

        /// <summary>
        /// The allowed time difference between the reported time and the time in the timestamp.
        /// </summary>
        /// <remarks>
        /// The provider or reported time is always somewhat before the time in the timestamp because the timestamp can only
        /// be created afterward.  This property specifies how much before is acceptable.
        /// </remarks>
        /// <value>Get or sets the timestamp grace period</value>
        public TimeSpan TimestampGracePeriod
        {
            get
            {
                return timestampGracePeriod;
            }
            set
            {
                timestampGracePeriod = value;
            }
        }

        /// <summary>
        /// Set to trust a specific Timestamp authority.
        /// </summary>
        /// <remarks>
        /// When you want to trust a specific timestamp authority, or the timestamp token does not contain the
        /// certificates, this property can be used to trust a specific (single) TSA.
        /// </remarks>
        public X509Certificate2 TrustedTsaCert
        {
            get
            {
                return trustedTsaCert;
            }
            set
            {
                trustedTsaCert = value;
            }
        }

        public XadesVerifier()
        {
            timestampGracePeriod = new TimeSpan(0, 10, 0);

            var doc = new XmlDocument();
            nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");
            nsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        }

        /// <summary>
        /// Verify any XAdES (-BES, -T) signature.
        /// </summary>
        /// <remarks>
        /// Requires the XAdES QualifyingProperties and not the signature, it will resolve the signature itself.
        /// </remarks>
        /// <param name="doc">The document for which the </param>
        /// <param name="xadesProps">The XAdES 1.4.1 QualifyingProperties xml-element</param>
        /// <returns>The (useful) information of the signature and xades properties</returns>
        /// <exception cref="ArgumentNullException">When the xades props param is null</exception>
        /// <exception cref="InvalidXadesException">When the XAdES isn't correctly formatted</exception>
        /// <exception cref="XadesValidationException">When the signature isn't valid</exception>
        /// <exception cref="NotSupportedException">When a XAdES or the signature contains unsupported sections</exception>
        public SignatureInfo Verify(XmlDocument doc, XmlElement xadesProps)
        {
            XadesForm form = XadesForm.XadesBes;

            if (xadesProps == null) throw new ArgumentNullException("xadesProps", "The xades props argument can't be null");

            //check if we get a valid xades-props
            //TODO:support QualifyingPropertiesReference
            if (xadesProps.LocalName != "QualifyingProperties" || xadesProps.NamespaceURI != "http://uri.etsi.org/01903/v1.3.2#") 
                throw new InvalidXadesException("The provider xades properties aren't actually xades properties");
            
            //Get the correpsonding signature of the xades props
            String targetRef;
            if (xadesProps.Attributes["Target"] == null) throw new InvalidXadesException("the XAdES Properties has no Target attribute defined");
            targetRef = xadesProps.Attributes["Target"].Value;
            if (targetRef == null || !targetRef.StartsWith("#")) throw new InvalidXadesException("the XAdES Properties has an invalid Target attribute value");
            var signatureNode = (XmlElement) xadesProps.OwnerDocument.SelectSingleNode("//ds:Signature[@Id='" + targetRef.Substring(1) + "']", nsMgr);
            if (signatureNode == null) throw new InvalidXadesException("The signature referenced by the XAdES Properties was not found (Target-attribute)");

            //Load the signature
            var signature = new SignedXml(doc);
            signature.LoadXml(signatureNode);

            //check if the signature contains a reference to the xades signed props.
            var xadesRef = new Reference();
            var signedPropsIdAttr = (XmlAttribute) xadesProps.SelectSingleNode("./xades:SignedProperties/@Id", nsMgr);
            if (signedPropsIdAttr == null) throw new InvalidXadesException("The xades Signed Properties do not have an Id which should be referenced in the signature");
            var xadesRefNode = (XmlElement) signatureNode.SelectSingleNode("./ds:SignedInfo/ds:Reference[@Type='http://uri.etsi.org/01903#SignedProperties']", nsMgr);
            if (xadesRefNode == null) throw new InvalidXadesException("The signature referenced by the XAdES Properties does not contain a reference element of te type 'http://uri.etsi.org/01903#SignedProperties'");
            xadesRef.LoadXml(xadesRefNode);
            if (xadesRef.Uri != ("#" + signedPropsIdAttr.Value)) throw new InvalidXadesException("The Signed Properties references does not reference the signed properties");

            //Check for illegal transforms in the reference to the xades signed props
            foreach (Transform t in xadesRef.TransformChain)
            {
                if (t.GetType() != typeof(XmlDsigC14NTransform) && t.GetType() != typeof(XmlDsigExcC14NTransform)) 
                    throw new InvalidXadesException(String.Format("The signed property reference does contain a transform that isn't allowed {0}", t.Algorithm));
            }

            //Get the provided certificates
            X509Certificate2Collection includedCerts = null;
            IEnumerator keyInfo = signature.Signature.KeyInfo.GetEnumerator();
            while (keyInfo.MoveNext())
            {
                KeyInfoClause clause = (KeyInfoClause) keyInfo.Current;
                if (clause.GetType() == typeof(KeyInfoX509Data))
                {
                    KeyInfoX509Data x509 = (KeyInfoX509Data)clause;
                    includedCerts = new X509Certificate2Collection((X509Certificate2[]) x509.Certificates.ToArray(typeof(X509Certificate2)));
                }
                else 
                {
                    throw new NotSupportedException("Only X509Data is supported");
                }
            }
            if (includedCerts == null) throw new InvalidXadesException("No certificates where found in the the signature key info");

            //Select the correct certificate based on the xades-bes info
            XmlNodeList signedCerts = xadesProps.SelectNodes("./xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert", nsMgr);
            //TODO:Support the fact that it is also legal to sign the KeyInfo (G.2.2.1)
            if (signedCerts.Count == 0) throw new InvalidXadesException("No signing certificates provided in the xades information");

            //Find certs via signed info, checking with hash.
            ICollection<X509Certificate2> verifiedCerts = new LinkedList<X509Certificate2>();
            foreach (XmlNode signedCert in signedCerts)
            {
                XmlNode issuerTxtNode = signedCert.SelectSingleNode("./xades:IssuerSerial/ds:X509IssuerName/text()", nsMgr);
                if (issuerTxtNode == null) throw new InvalidXadesException("Xades information does not contain an issuer name for the signing certificate");
                XmlNode serialNumberTxtNode = signedCert.SelectSingleNode("./xades:IssuerSerial/ds:X509SerialNumber/text()", nsMgr);
                if (serialNumberTxtNode == null) throw new InvalidXadesException("Xades information does not contain an serial number for the signing certificate");

                X509Certificate2Collection certsSameIssuer = includedCerts.Find(X509FindType.FindByIssuerDistinguishedName, issuerTxtNode.Value, false);
                if (certsSameIssuer.Count == 0) throw new InvalidXadesException(String.Format("Xades provided signing certificate {0} ({1}) can't be found in the key info", serialNumberTxtNode.Value, issuerTxtNode.Value));
                X509Certificate2Collection exactCerts = certsSameIssuer.Find(X509FindType.FindBySerialNumber, serialNumberTxtNode.Value, false);
                if (exactCerts.Count == 0) throw new InvalidXadesException(String.Format("Xades provided signing certificate {0} ({1}) can't be found in the key info", serialNumberTxtNode.Value, issuerTxtNode.Value));
                if (exactCerts.Count > 1) throw new InvalidXadesException(String.Format("Xades provided signing certificate {0} ({1}) can be found more then once in the key info", serialNumberTxtNode.Value, issuerTxtNode.Value));

                XmlNode digestMethodTxtNode = signedCert.SelectSingleNode("./xades:CertDigest/ds:DigestMethod/@Algorithm", nsMgr);
                if (digestMethodTxtNode == null) throw new InvalidXadesException("Xades information does not contain the digest method for the signing certificate");
                XmlNode digestValueTxtNode = signedCert.SelectSingleNode("./xades:CertDigest/ds:DigestValue/text()", nsMgr);
                if (digestValueTxtNode == null) throw new InvalidXadesException("Xades information does not contain the digest value for the signing certificate");

                HashAlgorithm algo;
                try
                {
                    algo = (HashAlgorithm)CryptoConfig.CreateFromName(digestMethodTxtNode.Value);
                }
                catch (Exception e)
                {
                    throw new InvalidXadesException("The provided digest method of the signing certificate in xades isn't valid or isn't supported", e);
                }
                String digestValueReal = Convert.ToBase64String(algo.ComputeHash(exactCerts[0].GetRawCertData()));
                if (digestValueTxtNode.Value != digestValueReal) throw new XadesValidationException("The certificate of the key info isn't correct according to the certificate info in xades");

                verifiedCerts.Add(exactCerts[0]);
            }

            //Check if any of the verified certificates is used for the signature
            bool valid = false;
            X509Certificate2 signingCert = null;
            IEnumerator<X509Certificate2> vce = verifiedCerts.GetEnumerator();
            while (!valid && vce.MoveNext())
            {
                signingCert = vce.Current;
                valid = signature.CheckSignature(signingCert, true);
            }
            if (!valid) throw new XadesValidationException("The signature is invalid");

            //Signing time retreval
            DateTimeOffset? signingTime = null;
            XmlNode signingTimeTxtNode = xadesProps.SelectSingleNode("./xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime/text()", nsMgr);
            if (signingTimeTxtNode != null)
            {
                DateTimeOffset signingTimeValue;
                if (!DateTimeOffset.TryParse(signingTimeTxtNode.Value, CultureInfo.InvariantCulture, DateTimeStyles.None, out signingTimeValue))
                    throw new InvalidXadesException("Signing time provided in the xades information isn't valid");
                signingTime = signingTimeValue;
            }
           
            //TODO:check for EPES.

            //TODO:check timestamp
            XmlNodeList timestamps = xadesProps.SelectNodes("./xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp", nsMgr);
            if (timestamps != null && timestamps.Count > 0)
            {
                form = XadesForm.XadesT;
                foreach (XmlNode timestamp in timestamps)
                {
                    XmlNode timestampC14NAlgoNode = timestamp.SelectSingleNode("./ds:CanonicalizationMethod/@Algorithm", nsMgr);
                    if (timestampC14NAlgoNode == null) new InvalidXadesException("Canonicalization method missing in the signature timestamp");

                    var signatureValue = (XmlElement)signatureNode.SelectSingleNode("./ds:SignatureValue", nsMgr);
                    if (signatureValue == null) throw new InvalidXadesException("Can't find the signature value for the signature timestamp");

                    var timestampC14NAlgo = (Transform) CryptoConfig.CreateFromName(timestampC14NAlgoNode.Value);
                    if (timestampC14NAlgo.GetType() != typeof(XmlDsigC14NTransform) && timestampC14NAlgo.GetType() != typeof(XmlDsigExcC14NTransform))
                        throw new InvalidXadesException(String.Format("The signature timestamp has a canonicalization method that isn't allowed {0}", timestampC14NAlgoNode.Value));

                    //Serialize because the C14N overloads wich accepts lists is totaly wrong (it C14N's the document)
                    MemoryStream stream = new MemoryStream();
                    using (var writer = XmlWriter.Create(stream))
                    {
                        signatureValue.WriteTo(writer);
                    }
                    stream.Seek(0, SeekOrigin.Begin);

                    //Canocalize the signature value
                    timestampC14NAlgo.LoadInput(stream);
                    var canonicalized = (Stream)timestampC14NAlgo.GetOutput(typeof(Stream));

                    XmlNode timestampValueTxtNode = timestamp.SelectSingleNode("./xades:EncapsulatedTimeStamp/text()", nsMgr);
                    if (timestampValueTxtNode != null)
                    {
                        //Get the timestamp token
                        TimeStampToken tst = new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(Convert.FromBase64String(timestampValueTxtNode.Value)));

                        //Compute the hash of the signature value, based on the hash algo in the timestamp
                        if (tst.TimeStampInfo.HashAlgorithm.Parameters != DerNull.Instance)
                            throw new NotSupportedException("Only hash algorithms without params are currently supported for timestamps"); //TODO: support algo's with params
                        if (tst.TimeStampInfo.Nonce != null)
                            throw new NotSupportedException("Timestamp with a nonce isn't supported"); //TODO: support nonce for timestamp
                        var hashAlogOid = new Oid(tst.TimeStampInfo.HashAlgorithm.ObjectID.Id);
                        var hashAlgo = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlogOid.FriendlyName);
                        byte[] signatureValueHashed = hashAlgo.ComputeHash(canonicalized);

                        //verify the hash value
                        byte[] timestampHash = tst.TimeStampInfo.TstInfo.MessageImprint.GetHashedMessage();
                        if (!((IStructuralEquatable)signatureValueHashed).Equals(timestampHash, StructuralComparisons.StructuralEqualityComparer))
                            throw new XadesValidationException("The timestamp doesn't match the signature value");

                        //check the timestamp token against the signing time.
                        //TODO:check better
                        DateTime tsTime = tst.TimeStampInfo.GenTime;
                        if (signingTime == null)
                        {
                            DateTime signingTimeUtc = signingTime.Value.UtcDateTime;
                            if (Math.Abs((tsTime - signingTimeUtc).TotalSeconds) > timestampGracePeriod.TotalSeconds) throw new XadesValidationException("The signature timestamp it to old with regards to the siging time");
                        }

                        //verify timestamp certificate
                        if (trustedTsaCert == null)
                        {
                            IX509Store store = tst.GetCertificates("Collection");
                            ICollection signers = store.GetMatches(tst.SignerID);
                            if (signers.Count == 0) throw new InvalidOperationException("No certificates present in the timestamp and not trusted TSA certificate provided, please provide a trusted TSA certificate");
                            if (signers.Count > 1) throw new InvalidOperationException("Multiple matching certificates present in the timstamp");

                            foreach(Org.BouncyCastle.X509.X509Certificate cert in signers)
                            {
                                try
                                {
                                    tst.Validate((Org.BouncyCastle.X509.X509Certificate)cert);
                                }
                                catch (Exception e)
                                {
                                    throw new XadesValidationException("The timestamp isn't issued by the TSA provided in the timestamp", e);
                                }
                            }

                            X509Chain tsaChain = new X509Chain();
                            foreach(Org.BouncyCastle.X509.X509Certificate cert in store.GetMatches(null)) 
                            {
                                tsaChain.ChainPolicy.ExtraStore.Add(new X509Certificate2(cert.GetEncoded()));
                            }
                            tsaChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                            tsaChain.ChainPolicy.RevocationMode = X509RevocationMode.Online; //TODO: configurable
                            tsaChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag; //TODO: configurable
                            tsaChain.ChainPolicy.VerificationTime = tst.TimeStampInfo.GenTime;
                            tsaChain.Build(signingCert);

                            foreach (X509ChainElement chainE in tsaChain.ChainElements)
                            {
                                if (chainE.ChainElementStatus.Length > 0 && chainE.ChainElementStatus[0].Status != X509ChainStatusFlags.NoError)
                                    throw new XadesValidationException(String.Format("The timestamp TSA chain contains an invalid certificate '{0}' ({1}: {2})",
                                        chainE.Certificate.Subject, chainE.ChainElementStatus[0].Status, chainE.ChainElementStatus[0].StatusInformation));
                            }
                        }
                        else
                        {
                            Org.BouncyCastle.X509.X509CertificateParser bcCertParser = new Org.BouncyCastle.X509.X509CertificateParser();
                            Org.BouncyCastle.X509.X509Certificate bcTrustedTsa = bcCertParser.ReadCertificate(trustedTsaCert.GetRawCertData());
                            try
                            {
                                tst.Validate(bcTrustedTsa);
                            }
                            catch (Exception e)
                            {
                                throw new XadesValidationException("The timestamp isn't issued by the trusted TSA", e);
                            }
                        }
                    }
                    else
                    {
                        //TODO:support xml timestamps
                        throw new NotSupportedException("Only Encapsulated timestamps are supported");
                    }
                    
                }
            }

            //Certificate validation
            //TODO:support profiles > XAdES-T
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(includedCerts);
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online; //TODO: configurable
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag; //TODO: configurable
            chain.ChainPolicy.VerificationTime = signingTime == null? DateTime.Now : signingTime.Value.LocalDateTime;
            chain.Build(signingCert);  //check each cert instead of the result

            //check the status of the individual certificates
            X509Certificate2[] usedCertArray = new X509Certificate2[verifiedCerts.Count];
            verifiedCerts.CopyTo(usedCertArray, 0);
            X509Certificate2Collection usedCerts = new X509Certificate2Collection(usedCertArray);
            foreach(X509ChainElement chainE in chain.ChainElements)
            {
                if (chainE.ChainElementStatus.Length > 0 && chainE.ChainElementStatus[0].Status != X509ChainStatusFlags.NoError)
                    throw new XadesValidationException(String.Format("The signing certificate chain contains an invalid certificate '{0}' ({1}: {2})",
                        chainE.Certificate.Subject, chainE.ChainElementStatus[0].Status, chainE.ChainElementStatus[0].StatusInformation));
                if (usedCerts.Contains(chainE.Certificate)) usedCerts.Remove(chainE.Certificate);
            }
            if (usedCerts.Count > 0) throw new XadesValidationException("Xades contains info contains references to unused certificates");

            return new SignatureInfo(form, signingCert, signingTime);
        }
    }
}
