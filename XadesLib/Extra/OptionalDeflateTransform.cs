/*
 *  This file is part of Xades Lib.
 *  Copyright (C) 2012 I.M. vzw
 *
 *  Xades Lib is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  Xades Lib is distributed in the hope that it will be useful,
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
using System.Security.Cryptography.Xml;
using System.IO;
using System.Xml;
using System.IO.Compression;

namespace IM.Xades.Extra
{
    /// <summary>
    /// XML-Transsform to inflate binary content.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Compliant with the conditional-deflate transform as defined by MyCareNet.
    /// </para>
    /// <para>
    /// Only supports stream as input, so should be used after a base64 transform: <see cref="System.Security.Cryptography.Xml.XmlDsigBase64Transform"/>.
    /// </para>
    /// </remarks>
    /// <value>Implements <literal>urn:nippin:xml:sig:transform:optional-deflate</literal></value>
    public class OptionalDeflateTransform : Transform
    {
        internal const String AlgorithmUri = "urn:nippin:xml:sig:transform:optional-deflate";

        private static readonly Type[] inputTypes = new Type[]
		{
			typeof(Stream)
		};

        private static readonly Type[] outputTypes = new Type[]
		{
			typeof(Stream)
		};

        private DeflateStream efs;

        /// <summary>
        /// Property used by by the library.
        /// </summary>
        public override Type[] InputTypes
        {
            get
            {
                return inputTypes;
            }
        }

        /// <summary>
        /// Property used by by the library.
        /// </summary>
        public override Type[] OutputTypes
        {
            get
            {
                return outputTypes;
            }
        }

        /// <summary>
        /// Default constuctor.
        /// </summary>
        public OptionalDeflateTransform()
        {
            base.Algorithm = AlgorithmUri;
        }

        /// <summary>
        /// Not used, not implemented.
        /// </summary>
        /// <param name="nodeList">The xml to load</param>
        public override void LoadInnerXml(XmlNodeList nodeList)
        {

        }

        /// <summary>
        /// Not used.
        /// </summary>
        /// <returns>
        /// Always <c>null</c>.
        /// </returns>
        protected override XmlNodeList GetInnerXml()
        {
            return null;
        }

        /// <summary>
        /// Method used by the library, do not call.
        /// </summary>
        /// <param name="obj">The stream to load as imput</param>
        public override void LoadInput(object obj)
        {
            Stream s = obj as Stream;
            if (s != null)
            {
                efs = new DeflateStream(s, CompressionMode.Decompress, true);
            }
            else
            {
                throw new ArgumentException("Object type isn't supported", "obj");
            }
        }

        /// <summary>
        /// Method used by the library, do not call.
        /// </summary>
        /// <returns>
        /// The enflating stream.
        /// </returns>
        public override object GetOutput()
        {
            return efs;
        }

        /// <summary>
        /// Method used by the library, do not call.
        /// </summary>
        /// <param name="type">The type of output that is required</param>
        /// <returns>
        /// The enflating stream
        /// </returns>
        public override object GetOutput(Type type)
        {
            if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
            {
                throw new ArgumentException("Type isn't supported", "type");
            }
            return efs;
        }
    }
}
