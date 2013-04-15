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

namespace IM.Xades
{
    /// <summary>
    /// Information about a (validated) XAdES signature.
    /// </summary>
    /// <remarks>
    /// Contains the required information about a validated XAdES signature.
    /// </remarks>
    public class SignatureInfo
    {
        private XadesForm form;

        /// <summary>
        /// The form of the XAdES signature validated.
        /// </summary>
        /// <value>
        /// Contains all the forms that apply for the signature (e.g. XadesBes | XadesT)
        /// </value>
        public XadesForm Form
        {
            get { return form; }
        }

        private X509Certificate2 certificate;

        /// <summary>
        /// The certificate used to sign.
        /// </summary>
        /// <value>
        /// Indentifies the person who signed the message that corresponds to the signature.
        /// </value>
        public X509Certificate2 Certificate
        {
            get { return certificate; }
        }

        private DateTimeOffset? time;

        /// <summary>
        /// The time the signature was create, if present.
        /// </summary>
        /// <value>
        /// If a time is provided, it is returned here (after validation).
        /// </value>
        public DateTimeOffset? Time
        {
            get { return time; }
        }

        private ManifestResult[] manifestResults;

        public ManifestResult[] ManifestResult
        {
            get { return manifestResults; }
        }

        internal SignatureInfo(XadesForm form, X509Certificate2 certificate, DateTimeOffset? time, ManifestResult[] manifestResults)
        {
            this.form = form;
            this.certificate = certificate;
            this.time = time;
            this.manifestResults = manifestResults;
        }
    }
}
