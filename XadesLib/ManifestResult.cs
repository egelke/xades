using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace IM.Xades
{
    public class ManifestResult
    {
        private static XmlNamespaceManager nsMgr;

        public static XmlNamespaceManager NsMgr
        {
            get { return nsMgr; }
        }

        static ManifestResult()
        {
            var doc = new XmlDocument();
            nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        }

        private String referenceXpath;

        public String ReferenceXpath
        {
            get { return referenceXpath; }
        }

        private ManifestResultStatus status;

        public ManifestResultStatus Status
        {
            get { return status; }
        }

        internal ManifestResult(String referenceXpath, ManifestResultStatus status)
        {
            this.referenceXpath = referenceXpath;
            this.status = status;
        }
    }
}
