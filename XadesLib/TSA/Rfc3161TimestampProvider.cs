using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using Org.BouncyCastle.Tsp;
using System.IO;
using System.Security.Cryptography;

namespace IM.Xades.TSA
{
    public class Rfc3161TimestampProvider : ITimestampProvider
    {
        private Uri address;

        /// <summary>
        /// RFC3161 toward Fedict.
        /// </summary>
        /// <remarks>
        /// You may only use this when you have the explicit agreement of Fedict. 
        /// </remarks>
        public Rfc3161TimestampProvider()
        {
            address = new Uri("http://tsa.belgium.be/connect");
        }

        public Rfc3161TimestampProvider(Uri address)
        {
            this.address = address;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="digestMethod"></param>
        /// <returns></returns>
        /// <exception cref="WebException">When the TSA returned a http-error</exception>
        /// <exception cref="TspValidationException">When the TSA returns an invalid timestamp response</exception>
        public byte[] GetTimestampFromDocumentHash(byte[] hash, string digestMethod)
        {
            String digestOid = CryptoConfig.MapNameToOID(CryptoConfig.CreateFromName(digestMethod).GetType().ToString());

            TimeStampRequestGenerator tsprg = new TimeStampRequestGenerator();
            tsprg.SetCertReq(true);
            TimeStampRequest tspr = tsprg.Generate(digestOid, hash);
            byte[] tsprBytes = tspr.GetEncoded();

            WebRequest post = WebRequest.Create(address);
            post.ContentType = "application/timestamp-query";
            post.Method = "POST";
            post.ContentLength = tsprBytes.Length;
            using (Stream postStream = post.GetRequestStream())
            {
                postStream.Write(tsprBytes, 0, tsprBytes.Length);
            }
            WebResponse response = post.GetResponse();
            if (response.ContentType != "application/timestamp-reply")
            {
                throw new ApplicationException("Response with invalid content type of the TSA: " + response.ContentType);
            }
            Stream responseStream = response.GetResponseStream();

            TimeStampResponse tsResponse = new TimeStampResponse(responseStream);
            tsResponse.Validate(tspr);

            return tsResponse.TimeStampToken.GetEncoded();
        }
    }
}
