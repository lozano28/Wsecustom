using System;
using System.Web.Services.Protocols;
using System.Collections.Generic;
using System.Text;
using System.Xml.Serialization;

namespace UsernameAssertionLibrary
{
    /// <summary>
    /// This is base class for all custom SOAP headers that should be encrypted in the response.
    /// </summary>
    public class SecureSoapHeader : SoapHeader
    {
        /// <summary>
        /// This property is just a flag telling us that this SOAP header should be encrypted.
        /// </summary>
        [XmlAttribute("SecureHeader", Namespace="http://company.com/samples/wse/")]
        public bool SecureHeader;
    }
}
