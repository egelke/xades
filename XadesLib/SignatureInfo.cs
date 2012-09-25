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

    public class SignatureInfo
    {
        private XadesForm form;

        public XadesForm Form
        {
            get { return form; }
            set { form = value; }
        }

        private X509Certificate2 certificate;

        public X509Certificate2 Certificate
        {
            get { return certificate; }
            set { certificate = value; }
        }
        private DateTimeOffset? time;

        public DateTimeOffset? Time
        {
            get { return time; }
            set { time = value; }
        }

        internal SignatureInfo(XadesForm form, X509Certificate2 certificate, DateTimeOffset? time)
        {
            this.form = form;
            this.certificate = certificate;
            this.time = time;
        }
    }
}
