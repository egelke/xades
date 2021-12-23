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

using IM.Xades;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Text;
using System.Security.Cryptography.Xml;
using System.IO;
using System.Xml.Serialization;
using System.ServiceModel;
using System.ServiceModel.Description;
using IM.Xades.Extra;
using System.Collections.Generic;
using Egelke.EHealth.Client.Pki.DSS;
using Egelke.EHealth.Client.Sso.Sts;
using Egelke.EHealth.Client.Pki;
using System.Linq;
using Xunit;

namespace IM.Xades.Test
{
    
    public class XadesTest
    {
        private XmlDocument document;

        private X509Certificate2 auth;
        private X509Certificate2 sign;
        private X509Certificate2Collection extraCerts;
        private TimeStampAuthorityClient tsa;

        public XadesTest()
        {
            var ehP12 = new EHealthP12(@"data\MYCARENET.p12", File.ReadAllText(@"data\MYCARENET.pwd"));
            auth = ehP12["authentication"];
            sign = ehP12["authentication"];
            extraCerts = ehP12.ToCollection();

            //load test document as xml
            document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(@"data\document.xml");


            //create the tsa
            tsa = new TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            tsa.ClientCredentials.ClientCertificate.Certificate = auth;
        }


        [Fact]
        public void CreatorConstructorParamNull()
        {
            Assert.Throws<ArgumentNullException>(() => new XadesCreator(null));
        }

        /*
        [Fact]
        public void CreatorConstructorParamInval()
        {
            Assert.Throws<ArgumentException>(() => new XadesCreator(tsaCerts[0]));
        }
        */

        [Fact]
        public void CreatorSignParamNull()
        {
            var xigner = new XadesCreator(sign);


            Assert.Throws<ArgumentNullException>(() => xigner.CreateXadesBes(null));
        }

        [Fact]
        public void VerifierVerifyParam1Null()
        {
            var xerifer = new XadesVerifier();


            Assert.Throws<ArgumentNullException>(() => xerifer.Verify(null, null));
        }

        [Fact]
        public void VerifierVerifyParam2Null()
        {
            var xerifer = new XadesVerifier();

            Assert.Throws<ArgumentNullException>(() => xerifer.Verify(new XmlDocument(), null));
        }

        [Fact]
        public void RoundTestXadesBes()
        {
            var xigner = new XadesCreator(sign, true, extraCerts);
            xigner.DataTransforms.Add(new XmlDsigBase64Transform());
            xigner.DataTransforms.Add(new OptionalDeflateTransform());
            var xades = xigner.CreateXadesBes(document, "_D4840C96-8212-491C-9CD9-B7144C1AD450");

            //Output for debugging
            var xml = new StringBuilder();
            var writerSettings = new XmlWriterSettings
            {
                Indent = true
            };
            using (var writer = XmlWriter.Create(xml, writerSettings))
            {
                xades.WriteTo(writer);
            }
            System.Console.WriteLine(xml.ToString());

            //Output for reading
            MemoryStream stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream))
            {
                xades.WriteTo(writer);
            }
            stream.Seek(0, SeekOrigin.Begin);

            var xades2 = new XmlDocument();
            xades2.PreserveWhitespace = true;
            xades2.Load(stream);

            var xerifier = new XadesVerifier();
            var info = xerifier.Verify(document, (XmlElement)XadesTools.FindXadesProperties(xades2)[0]);

            Assert.NotNull(info);
            Assert.NotNull(info.Certificate);
            Assert.Equal(sign, info.Certificate);
            Assert.Equal(XadesForm.XadesBes, info.Form);
            Assert.NotNull(info.Time);
            Assert.True((DateTimeOffset.Now - info.Time.Value) < new TimeSpan(0, 5, 0));
            Assert.Empty(info.ManifestResult);
        }

        [Fact]
        public void RountTestXadesTFullDoc()
        {
            var xigner = new XadesCreator(sign, true, extraCerts);
            xigner.TimestampProvider = new EHealthTimestampProvider(tsa);

            var xades = xigner.CreateXadesT(document);

            var xml = new StringBuilder();
            var writerSettings = new XmlWriterSettings
            {
                Indent = true
            };
            using (var writer = XmlWriter.Create(xml, writerSettings))
            {
                xades.WriteTo(writer);
            }
            System.Console.WriteLine(xml.ToString());

            MemoryStream stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream))
            {
                xades.WriteTo(writer);
            }
            stream.Seek(0, SeekOrigin.Begin);

            var xades2 = new XmlDocument();
            xades2.PreserveWhitespace = true;
            xades2.Load(stream);

            var xerifier = new XadesVerifier();
            var info = xerifier.Verify(document, (XmlElement)XadesTools.FindXadesProperties(xades2)[0]);

            Assert.NotNull(info);
            Assert.NotNull(info.Certificate);
            Assert.Equal(sign, info.Certificate);
            Assert.Equal(XadesForm.XadesBes | XadesForm.XadesT, info.Form);
            Assert.NotNull(info.Time);
            Assert.True((DateTimeOffset.Now - info.Time.Value) < new TimeSpan(0, 5, 0));
            Assert.Empty(info.ManifestResult);
        }

        [Fact]
        public void RoundTestXadesT()
        {
            var xigner = new XadesCreator(sign, true, extraCerts);
            xigner.TimestampProvider = new EHealthTimestampProvider(tsa);
            xigner.DataTransforms.Add(new XmlDsigBase64Transform());
            xigner.DataTransforms.Add(new OptionalDeflateTransform());

            var xades = xigner.CreateXadesT(document, "_D4840C96-8212-491C-9CD9-B7144C1AD450");

            var xml = new StringBuilder();
            var writerSettings = new XmlWriterSettings
            {
                Indent = true
            };
            using (var writer = XmlWriter.Create(xml, writerSettings))
            {
                xades.WriteTo(writer);
            }
            System.Console.WriteLine(xml.ToString());

            MemoryStream stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream))
            {
                xades.WriteTo(writer);
            }
            stream.Seek(0, SeekOrigin.Begin);

            var xades2 = new XmlDocument();
            xades2.PreserveWhitespace = true;
            xades2.Load(stream);

            var xerifier = new XadesVerifier();
            var info = xerifier.Verify(document, (XmlElement)XadesTools.FindXadesProperties(xades2)[0]);

            Assert.NotNull(info);
            Assert.NotNull(info.Certificate);
            Assert.Equal(sign, info.Certificate);
            Assert.Equal(XadesForm.XadesBes | XadesForm.XadesT, info.Form);
            Assert.NotNull(info.Time);
            Assert.True((DateTimeOffset.Now - info.Time.Value) < new TimeSpan(0, 5, 0));
            Assert.Empty(info.ManifestResult);
        }

        [Fact]
        public void RoundTestXadesTViaFedict()
        {
            var xigner = new XadesCreator(sign, true, extraCerts);
            xigner.TimestampProvider = new Rfc3161TimestampProvider();
            xigner.DataTransforms.Add(new XmlDsigBase64Transform());
            xigner.DataTransforms.Add(new OptionalDeflateTransform());
            var xades = xigner.CreateXadesT(document, "_D4840C96-8212-491C-9CD9-B7144C1AD450");

            //Output for debugging
            var xml = new StringBuilder();
            var writerSettings = new XmlWriterSettings
            {
                Indent = true
            };
            using (var writer = XmlWriter.Create(xml, writerSettings))
            {
                xades.WriteTo(writer);
            }
            System.Console.WriteLine(xml.ToString());

            //Output for reading
            MemoryStream stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream))
            {
                xades.WriteTo(writer);
            }
            stream.Seek(0, SeekOrigin.Begin);

            var xades2 = new XmlDocument();
            xades2.PreserveWhitespace = true;
            xades2.Load(stream);

            var xerifier = new XadesVerifier();
            var info = xerifier.Verify(document, (XmlElement)XadesTools.FindXadesProperties(xades2)[0]);

            Assert.NotNull(info);
            Assert.NotNull(info.Certificate);
            Assert.Equal(sign, info.Certificate);
            Assert.Equal(XadesForm.XadesBes | XadesForm.XadesT, info.Form);
            Assert.NotNull(info.Time);
            Assert.True((DateTimeOffset.Now - info.Time.Value) < new TimeSpan(0, 5, 0));
            Assert.Empty(info.ManifestResult);
        }



    }
}
