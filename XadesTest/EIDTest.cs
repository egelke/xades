﻿using Egelke.EHealth.Client.Pki;
using Egelke.Eid.Client;
using IM.Xades.Extra;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Xunit;

namespace IM.Xades.Test
{
    public class EIDTest
    {
        [Fact]
        public void XadesBes()
        {
            X509Certificate2 sign;
            using (var readers = new Readers(ReaderScope.User))
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                var target = (EidCard)readers.ListCards().Where(c => c is EidCard).FirstOrDefault();
                Assert.True(target != null, "No eid inserted, please insert (test) eid");
                target.Open();

                store.Open(OpenFlags.ReadOnly);
                sign = store.Certificates.Find(X509FindType.FindByThumbprint, target.SignCert.Thumbprint, false)[0];
            }

            var document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(@"data\basic.xml");
            var xsigner = new XadesCreator(sign, true);
            var xades = xsigner.CreateXadesBes(document, "_1");
            document.DocumentElement.AppendChild(xades);

            // Output for reading
            MemoryStream stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream))
            {
                document.WriteTo(writer);
            }
            stream.Seek(0, SeekOrigin.Begin);

            var signed = new XmlDocument();
            signed.PreserveWhitespace = true;
            signed.Load(stream);

            var xerifier = new XadesVerifier();
            var info = xerifier.Verify(signed, (XmlElement)XadesTools.FindXadesProperties(signed)[0]);

            Assert.NotNull(info);
            Assert.NotNull(info.Certificate);
            Assert.Equal(sign, info.Certificate);
            Assert.Equal(XadesForm.XadesBes, info.Form);
            Assert.NotNull(info.Time);
            Assert.True((DateTimeOffset.Now - info.Time.Value) < new TimeSpan(0, 5, 0));
        }

        [Fact]
        public void XadesT()
        {
            X509Certificate2 sign;
            using (var readers = new Readers(ReaderScope.User))
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                var target = (EidCard)readers.ListCards().Where(c => c is EidCard).FirstOrDefault();
                Assert.True(target != null, "No eid inserted, please insert (test) eid");
                target.Open();

                store.Open(OpenFlags.ReadOnly);
                sign = store.Certificates.Find(X509FindType.FindByThumbprint, target.SignCert.Thumbprint, false)[0];
            }

            var document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(@"data\basic.xml");
            var xsigner = new XadesCreator(sign, true);
            xsigner.TimestampProvider = new Rfc3161TimestampProvider();
            var xades = xsigner.CreateXadesT(document, "_1");
            document.DocumentElement.AppendChild(xades);

            // Output for reading
            MemoryStream stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream))
            {
                document.WriteTo(writer);
            }
            stream.Seek(0, SeekOrigin.Begin);

            var signed = new XmlDocument();
            signed.PreserveWhitespace = true;
            signed.Load(stream);

            var xerifier = new XadesVerifier();
            var info = xerifier.Verify(signed, (XmlElement)XadesTools.FindXadesProperties(signed)[0]);

            Assert.NotNull(info);
            Assert.NotNull(info.Certificate);
            Assert.Equal(sign, info.Certificate);
            Assert.Equal(XadesForm.XadesBes, info.Form);
            Assert.NotNull(info.Time);
            Assert.True((DateTimeOffset.Now - info.Time.Value) < new TimeSpan(0, 5, 0));
        }
    }
}
