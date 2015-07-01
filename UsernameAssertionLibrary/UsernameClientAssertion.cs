using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

using Microsoft.Web.Services3;
using Microsoft.Web.Services3.Design;
using Microsoft.Web.Services3.Security;
using Microsoft.Web.Services3.Security.Tokens;

namespace UsernameAssertionLibrary
{
    public class UsernameClientAssertion : SecurityPolicyAssertion
    {
        private string username;
        private string password;

        public UsernameClientAssertion(string username, string password)
        {
            this.username = username;
            this.password = password;
        }

        public override SoapFilter CreateClientOutputFilter(FilterCreationContext context)
        {
            return new ClientOutputFilter(this, context);
        }

        public override SoapFilter CreateClientInputFilter(FilterCreationContext context)
        {
            // we don't provide ClientInputFilter
            return null;
        }

        public override SoapFilter CreateServiceInputFilter(FilterCreationContext context)
        {
            // we don't provide any processing for web service side
            return null;
        }

        public override SoapFilter CreateServiceOutputFilter(FilterCreationContext context)
        {
            // we don't provide any processing for web service side
            return null;
        }

        #region ClientOutputFilter
        class ClientOutputFilter : SendSecurityFilter
        {
            UsernameClientAssertion parentAssertion;
            FilterCreationContext filterContext;

            public ClientOutputFilter(UsernameClientAssertion parentAssertion, FilterCreationContext filterContext)
                : base(parentAssertion.ServiceActor, false, parentAssertion.ClientActor)
            {
                this.parentAssertion = parentAssertion;
                this.filterContext = filterContext;
            }

            public override void SecureMessage(SoapEnvelope envelope, Security security)
            {
                UsernameToken userToken = new UsernameToken(
                    parentAssertion.username,
                    parentAssertion.password,
                    PasswordOption.SendNone); // we don't send password over network
                                              // but we just use username/password to sign/encrypt message

                // Add the token to the SOAP header.
                security.Tokens.Add(userToken);

                // Sign the SOAP message by using the UsernameToken.
                MessageSignature sig = new MessageSignature(userToken);
                security.Elements.Add(sig);

                // encrypt BODY
                EncryptedData data = new EncryptedData(userToken);

                // encrypt custom headers
                for (int index = 0; index < envelope.Header.ChildNodes.Count; index++)
                {
                    XmlElement child = envelope.Header.ChildNodes[index] as XmlElement;

                    // find all SecureSoapHeader headers marked with a special attribute
                    if (child != null && child.NamespaceURI == "http://company.com/samples/wse/")
                    {
                        // create ID attribute for referencing purposes
                        string id = Guid.NewGuid().ToString();
                        child.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", id);

                        // Create an encryption reference for the custom SOAP header.
                        data.AddReference(new EncryptionReference("#" + id));
                    }
                }

                // add ancrypted data to the security context
                security.Elements.Add(data);
            }
        }
        #endregion
    }
}
