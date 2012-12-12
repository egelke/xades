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
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;

namespace IM.Xades.TSA
{
    /// <summary>
    /// Timestamp provider for TSA's that implement the DSS Timestamp profile.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Send a DSS-Sign request compliant with the timestamp profile to the TSA.
    /// </para>
    /// <para>
    /// The call is made via a WCF client, <see cref="DssTimestampProvider.DssTimestampProvider(TSA.DSS.TimeStampAuthorityClient)"/>
    /// </para>
    /// </remarks>
    public class DssTimestampProvider : ITimestampProvider
    {
        private TSA.DSS.TimeStampAuthorityClient client;

        /// <summary>
        /// The profile identifier to send to the TSA to request a timestamp.
        /// </summary>
        /// <value>
        /// The profile identifier, defaults to the standard value <literal>urn:oasis:names:tc:dss:1.0:profiles:timestamping</literal>.
        /// </value>
        protected String profile = "urn:oasis:names:tc:dss:1.0:profiles:timestamping";

        /// <summary>
        /// The profile identifier to send to the TSA to request a timestamp.
        /// </summary>
        /// <remarks>
        /// defaults to the standard value <literal>urn:oasis:names:tc:dss:1.0:profiles:timestamping</literal>.
        /// </remarks>
        /// <value>
        /// Gets and sets the profile identifier.
        /// </value>
        public String Profile
        {
            get
            {
                return profile;
            }
            set
            {
                profile = value;
            }
        }

        /// <summary>
        /// Default constructor using default TSA client of the application configuration.
        /// </summary>
        /// <remarks>
        /// <para>
        /// When this constructor is used, the application configuration is searched for a TSA client with the name "Xades.TSA".
        /// </para>
        /// <para>
        /// The exact configuration requirements depend on the TSA and should be obtained from them.
        /// </para>
        /// </remarks>
        public DssTimestampProvider()
        {
            client = new TSA.DSS.TimeStampAuthorityClient();
        }

        /// <summary>
        /// Constructor using a TSA client with the provided configuration.
        /// </summary>
        /// <remarks>
        /// <para>
        /// When this constructor is used, the application configuration is searched for a TSA client with the provided name.
        /// </para>
        /// <para>
        /// The exact configuration requirements depend on the TSA and should be obtained from them.
        /// </para>
        /// </remarks>
        /// <param name="config">The configuration name of the TSA client</param>
        public DssTimestampProvider(String config)
        {
            client = new TSA.DSS.TimeStampAuthorityClient(config);
        }

        /// <summary>
        /// Constructor using a provided TSA client.
        /// </summary>
        /// <remarks>
        /// <para>
        /// When this constructor is used, the application configuration isn't used.
        /// </para>
        /// <para>
        /// The exact configuration requirements depend on the TSA and should be obtained from them.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code language="C#">
        /// var tsa = new TSA.DSS.TimeStampAuthorityClient(new BasicHttpBinding(), new EndpointAddress("http://www.ca.com/TSA"));
        /// tsa.ClientCredentials.ClientCertificate.Certificate = certificate;
        /// var tsProvider = new DssTimestampProvider(tsa);
        /// </code>
        /// </example>
        /// <param name="client">The pre-configured instance of the TSA client.</param>
        public DssTimestampProvider(TSA.DSS.TimeStampAuthorityClient client)
        {
            this.client = client;
        }

        /// <summary>
        /// Method used by the library, not not call youself.
        /// </summary>
        /// <param name="hash">The hash on which the digesht must be calculated</param>
        /// <param name="digestMethod">The digest method with which the hash was calculated</param>
        /// <returns>The RFC3161 Timestamp token</returns>
        public virtual byte[] GetTimestampFromDocumentHash(byte[] hash, string digestMethod)
        {
            //create request
            TSA.DSS.SignRequest request = new TSA.DSS.SignRequest();

            //Set some standard value of the request
            request.RequestID = "_" + Guid.NewGuid().ToString("D");
            request.Profile = profile;

            //Create the document hash structure
            TSA.DSS.DocumentHash docHash = new TSA.DSS.DocumentHash();
            docHash.DigestMethod = new TSA.DSS.DigestMethodType();
            docHash.DigestMethod.Algorithm = digestMethod;
            docHash.DigestValue = hash;
            request.InputDocuments = new TSA.DSS.InputDocuments();
            request.InputDocuments.Items = new Object[] { docHash };

            //Send the request
            TSA.DSS.SignResponse resp = client.Stamp(request);

            if (resp.Result.ResultMajor != "urn:oasis:names:tc:dss:1.0:resultmajor:Success")
            {
                throw new ApplicationException(resp.Result.ResultMessage.Value);
            }

            return (byte[]) ((TSA.DSS.Timestamp)resp.SignatureObject.Item).Item;
        }
    }
}
