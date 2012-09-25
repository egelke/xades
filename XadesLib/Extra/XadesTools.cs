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

namespace IM.Xades.Extra
{
    /// <summary>
    /// Set of useful functions related to xades (except for sign an verify).
    /// </summary>
    public static class XadesTools
    {
        private static readonly XmlNamespaceManager nsMgr;

        static XadesTools()
        {
            nsMgr = new XmlNamespaceManager(new XmlDocument().NameTable);
            nsMgr.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");
        }

        /// <summary>
        /// Extacts all the XAdES quulifying properties out of the provided node.
        /// </summary>
        /// <param name="node">The node to look for xades qualifying properties</param>
        /// <returns>The list of properties found, can be emtpy if none are found</returns>
        public static XmlNodeList FindXadesProperties(XmlNode node)
        {
            return node.SelectNodes("//xades:QualifyingProperties", nsMgr);
        }
    }
}
