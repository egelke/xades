using IM.Xades.TSA;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Text;
using Siemens.EHealth.Client.Sso.Sts;
using System.ServiceModel;
using System.ServiceModel.Description;
using Siemens.EHealth.Client.Sso.WA;
using System.Security.Cryptography.X509Certificates;

namespace IM.Xades.Test
{
    
    
    /// <summary>
    ///This is a test class for EHealthTimestampProviderTest and is intended
    ///to contain all EHealthTimestampProviderTest Unit Tests
    ///</summary>
    [TestClass()]
    public class EHealthTimestampProviderTest
    {
        private static X509Certificate2 auth;
        private static TSA.DSS.TimeStampAuthorityClient tsa;

         [ClassInitialize]
        public static void MyClassInitialize(TestContext testContext)
        {
            //load certificates (fixed)
            auth = new X509Certificate2("MYCARENET.p12", "mycarenet");


            //create the tsa
            tsa = new TSA.DSS.TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/timestampauthority_1_5/timestampauthority"));
            tsa.Endpoint.Behaviors.Remove<ClientCredentials>();
            tsa.Endpoint.Behaviors.Add(new OptClientCredentials());
            tsa.ClientCredentials.ClientCertificate.Certificate = auth;
        }

         private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        // 
        //You can use the following additional attributes as you write your tests:
        //
        //Use ClassInitialize to run code before running the first test in the class
        //[ClassInitialize()]
        //public static void MyClassInitialize(TestContext testContext)
        //{
        //}
        //
        //Use ClassCleanup to run code after all tests in a class have run
        //[ClassCleanup()]
        //public static void MyClassCleanup()
        //{
        //}
        //
        //Use TestInitialize to run code before running each test
        //[TestInitialize()]
        //public void MyTestInitialize()
        //{
        //}
        //
        //Use TestCleanup to run code after each test has run
        //[TestCleanup()]
        //public void MyTestCleanup()
        //{
        //}
        //
        #endregion


        /// <summary>
        ///A test for GetTimestampFromDocumentHash
        ///</summary>
        [TestMethod()]
        public void GetTimestampFromDocumentHashTest()
        {
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes("Hello World!"));

            EHealthTimestampProvider target = new EHealthTimestampProvider(tsa);

            byte[] result = target.GetTimestampFromDocumentHash(hash, "http://www.w3.org/2001/04/xmlenc#sha256");

            Assert.IsNotNull(result);
        }
    }
}
