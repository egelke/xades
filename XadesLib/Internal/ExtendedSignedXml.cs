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
using System.Security.Cryptography.Xml;
using System.Xml;

namespace IM.Xades.Internal
{
    internal class ExtendedSignedXml : SignedXml
    {
        private readonly List<DataObject> dataObjects = new List<DataObject>();

        public ExtendedSignedXml(XmlDocument document) : base(document) 
        {
        
        }

        public override XmlElement GetIdElement(XmlDocument doc, string id)
        {
            var xmlElement = base.GetIdElement(doc, id);
            if (xmlElement != null)
            {
                return xmlElement;
            }
            
            foreach (var dataObject in dataObjects)
            {
                foreach (XmlNode data in dataObject.Data)
                {
                    var node = (XmlElement) data.SelectSingleNode("//*[@Id='" + id + "']");
                    if (node != null)
                    {
                        return node;
                    }
                }
            }
            return null;
        }

        public new void AddObject(DataObject dataObject)
        {
            base.AddObject(dataObject);
            dataObjects.Add(dataObject);
        }

    }
}
