using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace IM.Xades
{
    /// <summary>
    /// Information about the validation of a manifest in XMLDSig.
    /// </summary>
    public class ManifestResult
    {
        private static XmlNamespaceManager nsMgr;

        /// <summary>
        /// XML Namesapce Manager with the prefix declarations of the Reference XPath.
        /// </summary>
        /// <see cref="ReferenceXpath"/>
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

        /// <summary>
        /// The XPath to the reference that was validated.  The prefixes are defined
        /// in the NsMgr field.
        /// </summary>
        /// <see cref="NsMgr"/>
        public String ReferenceXpath
        {
            get { return referenceXpath; }
        }

        private ManifestResultStatus status;

        /// <summary>
        /// The outcome of the reference validation.
        /// </summary>
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
