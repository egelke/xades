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
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Reflection;
using System.IO;
using System.Globalization;
using System.Security.Cryptography;
using System.Numerics;
using Egelke.EHealth.Client.Pki;

namespace IM.Xades
{
    /// <summary>
    /// Create Xades compliaten XML-Signatures.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Targets the XAdES 1.4.1 standard.  Currently supports Xades-BES and Xades-T.  Other profiles may be added in the future.
    /// </para>
    /// </remarks>
    public class XadesCreator
    {
        static XadesCreator()
        {
            CryptoConfig.AddAlgorithm(typeof(Extra.RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        }

        private XmlNamespaceManager nsMgr;

        private XmlElement signObject;
        private XmlAttribute target;
        private XmlElement signTime;
        private XmlElement certDigestVal;
        private XmlElement issuerName;
        private XmlElement serialNbr;

        private X509Certificate2 certificate;
        private List<Transform> dataTransforms;
        private ITimestampProvider timestampProvider;

        /// <summary>
        /// The certificate with private key to sign with.
        /// </summary>
        /// <value>Get or set the certificate that will be used to sign with</value>
        public X509Certificate2 Certificate {
            get 
            {
                return certificate;
            }
            set 
            {
                certificate = value;
            }
        }

        /// <summary>
        /// XML Signature transforms that must be used on the reference of the data.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This are the transforms that will be applied on the signed data.  The transforms
        /// on the XAdES properties aren't impacted by this.
        /// </para>
        /// <para>
        /// By default there aren't any transforms, this means the default transform will be used.
        /// Add the required transformations in the order they should be excuted.
        /// </para>
        /// </remarks>
        /// <value>Get the xml signature transforms used on the data.</value>
        /// <seealso cref="Extra.OptionalDeflateTransform"/>
        /// <seealso cref="System.Security.Cryptography.Xml.Transform"/>
        public List<Transform> DataTransforms
        {
            get
            {
                return dataTransforms;
            }
        }

        /// <summary>
        /// The timestamp provider that will be used to obtain timestamps.
        /// </summary>
        /// <remarks>
        /// <para>
        /// XAdES-T and above require timestamp(s), this provider is used to obtain them.
        /// </para>
        /// <para>
        /// XAdES-BES does not require property to be set.
        /// </para>
        /// </remarks>
        /// <seealso cref="Egelke.EHealth.Client.Pki.Rfc3161TimestampProvider"/>
        /// <seealso cref="Egelke.EHealth.Client.Pki.DssTimestampProvider"/>
        /// <seealso cref="Egelke.EHealth.Client.Pki.EHealthTimestampProvider"/>
        /// <value>Get or set the instance to the timestamp provider or null</value>
        public ITimestampProvider TimestampProvider
        {
            get
            {
                return timestampProvider;
            }
            set
            {
                timestampProvider = value;
            }
        }

        /// <summary>
        /// Creates an new instance of the class with the singing certificate provided.
        /// </summary>
        /// <remarks>
        /// <para>
        /// In order to be able to sign the certificate must have a private key linked to it.  Certificate can either be retrieved from
        /// the windows key store or from a pkcs#12 file.
        /// </para>
        /// <para>
        /// Microsoft uses cryptographic providers to keep the keys.  The default crypto provider does not support SHA-256 and is therefore
        /// incompatible with this library.  The following providers are known to be supported:
        /// </para>
        /// <list type="bullet">
        ///     <item><description>Microsoft Enhanced RSA and AES Cryptographic Provider</description></item>
        ///     <item><description>Microsoft Enhanced Cryptographic Provider v1.0</description></item>
        /// </list>
        /// <para>
        /// PKCS#12 files with multiple private keys aren't supported and the cryto provider must be specified in the file which is rarely the case.
        /// Fortunately, it is possible to add the crypto provider by recreating it via OpenSSL via the following commands:
        /// </para>
        /// <command>openssl pkcs12 -in file.p12 -out file.pem</command>
        /// <command>openssl pkcs12 -export -in file.pem -out file.p12 -name MyCareNet -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider"</command>
        /// </remarks>
        /// <param name="certificate">Certificate with private key, will be used to sign the the message</param>
        /// <exception cref="ArgumentNullException">When the certificate param is null</exception>
        /// <exception cref="ArgumentException">When certificate doesn't contain a private key.</exception>
        public XadesCreator(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate", "Signing certificate must be provided");
            }
            if (!certificate.HasPrivateKey)
            {
                throw new ArgumentException("The certificate must be accompanied by a private key", "certificate");
            }

            this.certificate = certificate;
            this.dataTransforms = new List<Transform>();

            var qProps = new XmlDocument();
            qProps.Load(new MemoryStream(Properties.Resources.QualifyingProperties));
            signObject = qProps.DocumentElement;


            nsMgr = new XmlNamespaceManager(qProps.NameTable);
            nsMgr.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");
            nsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            target = (XmlAttribute)qProps.SelectSingleNode("//xades:QualifyingProperties/@Target", nsMgr);
            signTime = (XmlElement)qProps.SelectSingleNode("//xades:SigningTime", nsMgr);
            certDigestVal = (XmlElement)qProps.SelectSingleNode("//xades:CertDigest/ds:DigestValue", nsMgr);
            issuerName = (XmlElement)qProps.SelectSingleNode("//xades:IssuerSerial/ds:X509IssuerName", nsMgr);
            serialNbr = (XmlElement)qProps.SelectSingleNode("//xades:IssuerSerial/ds:X509SerialNumber", nsMgr);
        }

        /// <summary>
        /// Create a XAdES-BES signature, signing the entire document.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Creates a signature, where the entire document is signed.  It
        /// returns a detached signature that can be used seperatly or
        /// added to the document.  Before it can be added, it should be
        /// imported.
        /// </para>
        /// </remarks>
        /// <param name="doc">The XML doucment to sign</param>
        /// <returns>The XML-signature element containing the required XAdES structures</returns>
        /// <exception cref="ArgumentNullException">When the doc argument is null</exception>
        public XmlElement CreateXadesBes(XmlDocument doc)
        {
            return CreateXadesBes(doc, null);
        }

        /// <summary>
        /// Create a XAdES-BES signature, singing the the part with the provided reference.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Creates a signature, where only the requested element is signed.  It
        /// returns a detached signature that can be used seperatly or
        /// added to the document.  Before it can be added, it should be
        /// imported.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code language="C#">
        /// var xigner = new XadesCreator(certificate);
        /// xigner.TimestampProvider = new TSA.EHealthTimestampProvider(tsa);
        /// xigner.DataTransforms.Add(new XmlDsigBase64Transform());
        /// xigner.DataTransforms.Add(new OptionalDeflateTransform());
        /// var xades = xigner.CreateXadesT(document, "datailID");
        /// </code>
        /// </example>
        /// <param name="doc">XML document contains an element with an "Id" equal to the reference parameter</param>
        /// <param name="reference">The reference of the elmement to sign, without the #-sign</param>
        /// <returns>The XML-signature element containing the required XAdES structures.</returns>
        /// <exception cref="ArgumentNullException">When the doc argument is null</exception>
        public XmlElement CreateXadesBes(XmlDocument doc, String reference)
        {
            if (doc == null)
            {
                throw new ArgumentNullException("doc", "An xml document must be provider");
            }

            //prepare to sign
            Guid sId = Guid.NewGuid();
            var signedXml = new Internal.ExtendedSignedXml(doc);

            //Set the signingg key
            signedXml.SigningKey = certificate.PrivateKey;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            //Add the data reference
            var dataRef = new Reference(reference == null ? "" : "#" + reference);
            dataRef.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            if (dataTransforms.Count == 0)
            {
                if (reference == null)
                {
                    dataRef.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                }
                else
                {
                    dataRef.AddTransform(new XmlDsigExcC14NTransform());
                }
            }
            else
            {
                foreach(var transform in dataTransforms) {
                    dataRef.AddTransform(transform);
                }
            }
            signedXml.AddReference(dataRef);

            //add the xades reference
            var xadesRef = new Reference("#idSignedProperties");
            xadesRef.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            xadesRef.Type = "http://uri.etsi.org/01903#SignedProperties";
            xadesRef.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(xadesRef);

            //Add key info (self)
            var clause = new KeyInfoX509Data(certificate);
            signedXml.KeyInfo.AddClause(clause);
            //TODO: Add chain

            //Add data
            target.Value = "#_" + sId.ToString("D");
            signTime.InnerText = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK", CultureInfo.InvariantCulture);
            certDigestVal.InnerText = Convert.ToBase64String(SHA256.Create().ComputeHash(certificate.RawData));
            issuerName.InnerText = certificate.Issuer;
            serialNbr.InnerText = new BigInteger(certificate.GetSerialNumber()).ToString(CultureInfo.InvariantCulture);

            var dataObject = new DataObject();
            dataObject.LoadXml(signObject);
            signedXml.AddObject(dataObject);

            //Compute the signature
            signedXml.ComputeSignature();

            //Add the ID to the signature
            XmlElement ret = signedXml.GetXml();
            XmlAttribute sIdAttr = ret.OwnerDocument.CreateAttribute("Id");
            sIdAttr.Value = "_" + sId.ToString("D");
            ret.Attributes.Append(sIdAttr);

            return ret;
        }

        /// <summary>
        /// Add a timestamp to the signature, complaint with the XAdES-T 1.3.1 standard.
        /// </summary>
        /// <remarks>
        /// Requires a Timestamp Provider <see cref="XadesCreator.TimestampProvider"/>
        /// </remarks>
        /// <param name="signature">The signature to extend</param>
        /// <exception cref="ArgumentNullException">When the signature is null</exception>
        /// <exception cref="InvalidOperationException">When no timestamp provider is set</exception>
        public void ExtendToXadesT(ref XmlElement signature)
        {
            if (signature == null)
            {
                throw new ArgumentNullException("signature", "A signature is required");
            }
            if (timestampProvider == null)
            {
                throw new InvalidOperationException("The timestamp provider is required for XAdES-T");
            }

            var timestamp = new XmlDocument();
            timestamp.Load(new MemoryStream(Properties.Resources.Timestamp));
            var timestampValue = (XmlElement)timestamp.SelectSingleNode("//xades:EncapsulatedTimeStamp", nsMgr);

            XmlNode sigValue = signature.SelectSingleNode("./ds:SignatureValue", nsMgr);

            //Serialize because the C14N overloads wich accepts lists is totaly wrong (it C14N's the document)
            MemoryStream stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream))
            {
                sigValue.WriteTo(writer);
            }
            stream.Seek(0, SeekOrigin.Begin);

            //Canocalize the signature value
            XmlDsigExcC14NTransform transform = new XmlDsigExcC14NTransform();
            transform.LoadInput(stream);
            var canonicalized= (Stream) transform.GetOutput(typeof(Stream));

            //hash the canocalized version
            SHA256 sha256 = SHA256.Create();
            byte[] hashed = sha256.ComputeHash(canonicalized);

            //Get the timestamp.
            byte[] timestampHash = timestampProvider.GetTimestampFromDocumentHash(hashed, "http://www.w3.org/2001/04/xmlenc#sha256");

            timestampValue.InnerText = Convert.ToBase64String(timestampHash);

            var unsignedSigProps = (XmlElement)signature.SelectSingleNode("./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties", nsMgr);
            var imported = unsignedSigProps.OwnerDocument.ImportNode(timestamp.DocumentElement, true);
            unsignedSigProps.AppendChild(imported);
        }

        /// <summary>
        /// Create a XAdES-T signature, singing the the part with the provided reference.
        /// </summary>
        /// <remarks>
        /// Create a XAdES-BES and immedately extends it to a XAdES-T.
        /// </remarks>
        /// <param name="doc">XML document contains an element with an "Id" equal to the reference parameter</param>
        /// <param name="reference">The reference of the elmement to sign, without the #-sign</param>
        /// <returns>The XML-signature element containing the required XAdES structures.</returns>
        /// <seealso cref="XadesCreator.CreateXadesBes(XmlDocument, String)"/>
        /// <seealso cref="XadesCreator.ExtendToXadesT(ref XmlElement)"/>
        public XmlElement CreateXadesT(XmlDocument doc, String reference)
        {
            XmlElement signature = CreateXadesBes(doc, reference);
            ExtendToXadesT(ref signature);
            return signature;
        }

        /// <summary>
        /// Create a XAdES-T signature, singing the the entire document (enveloped).
        /// </summary>
        /// <remarks>
        /// Create a XAdES-BES and immedately extends it to a XAdES-T.
        /// </remarks>
        /// <param name="doc">XML document to be signed.</param>
        /// <returns>The XML-signature element containing the required XAdES structures.</returns>
        /// <seealso cref="XadesCreator.CreateXadesBes(XmlDocument)"/>
        /// <seealso cref="XadesCreator.ExtendToXadesT(ref XmlElement)"/>
        public XmlElement CreateXadesT(XmlDocument doc)
        {
            XmlElement signature = CreateXadesBes(doc);
            ExtendToXadesT(ref signature);
            return signature;
        }
    }
}
