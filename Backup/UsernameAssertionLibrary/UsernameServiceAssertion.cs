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
    public class UsernameServiceAssertion : SecurityPolicyAssertion
    {
        public UsernameServiceAssertion()
        {
        }

        public override SoapFilter CreateClientOutputFilter(FilterCreationContext context)
        {
            // we don't provide any processing for client side
            return null;
        }

        public override SoapFilter CreateClientInputFilter(FilterCreationContext context)
        {
            // we don't provide any processing for client side
            return null;
        }

        public override SoapFilter CreateServiceInputFilter(FilterCreationContext context)
        {
            return new ServiceInputFilter(this, context);
        }

        public override SoapFilter CreateServiceOutputFilter(FilterCreationContext context)
        {
            // we don't provide ServiceOutputFilter
            return null;
        }

        public override void ReadXml(XmlReader reader, IDictionary<string, Type> extensions)
        {
            if (reader == null)
                throw new ArgumentNullException("reader");
            if (extensions == null)
                throw new ArgumentNullException("extensions");

            // determine the name of the extension
            string tagName = null;
            foreach (string extName in extensions.Keys)
            {
                if (extensions[extName] == typeof(UsernameServiceAssertion))
                {
                    tagName = extName;
                    break;
                }
            }

            // read the first element (maybe empty)
            reader.ReadStartElement(tagName);
        }

        public override void WriteXml(XmlWriter writer)
        {
            // Typically this is not needed for custom policies
        }

        #region ClientOutputFilter
        public class ServiceInputFilter : ReceiveSecurityFilter
        {
            UsernameServiceAssertion parentAssertion;
            FilterCreationContext filterContext;

            public ServiceInputFilter(UsernameServiceAssertion parentAssertion, FilterCreationContext filterContext)
                : base(parentAssertion.ServiceActor, false, parentAssertion.ClientActor)
            {
                this.parentAssertion = parentAssertion;
                this.filterContext = filterContext;
            }

            public override void ValidateMessageSecurity(SoapEnvelope envelope, Security security)
            {
                bool IsSigned = false;
                if (security != null)
                {
                    foreach (ISecurityElement element in security.Elements)
                    {
                        if (element is MessageSignature)
                        {
                            // The given context contains a Signature element.
                            MessageSignature sign = element as MessageSignature;

                            if (CheckSignature(envelope, security, sign))
                            {
                                // The SOAP message is signed.
                                if (sign.SigningToken is UsernameToken)
                                {
                                    // The SOAP message is signed 
                                    // with a UsernameToken.
                                    IsSigned = true;
                                }
                            }
                        }
                    }
                }

                if (!IsSigned)
                    throw new SecurityFault("Message did not meet security requirements.");
            }

            private bool CheckSignature(SoapEnvelope envelope, Security security, MessageSignature signature)
            {
                //
                // Now verify which parts of the message were actually signed.
                //
                SignatureOptions actualOptions = signature.SignatureOptions;
                SignatureOptions expectedOptions = SignatureOptions.IncludeSoapBody;

                if (security != null && security.Timestamp != null)
                    expectedOptions |= SignatureOptions.IncludeTimestamp;

                //
                // The <Action> and <To> are required addressing elements.
                //
                expectedOptions |= SignatureOptions.IncludeAction;
                expectedOptions |= SignatureOptions.IncludeTo;

                if (envelope.Context.Addressing.FaultTo != null && envelope.Context.Addressing.FaultTo.TargetElement != null)
                    expectedOptions |= SignatureOptions.IncludeFaultTo;

                if (envelope.Context.Addressing.From != null && envelope.Context.Addressing.From.TargetElement != null)
                    expectedOptions |= SignatureOptions.IncludeFrom;

                if (envelope.Context.Addressing.MessageID != null && envelope.Context.Addressing.MessageID.TargetElement != null)
                    expectedOptions |= SignatureOptions.IncludeMessageId;

                if (envelope.Context.Addressing.RelatesTo != null && envelope.Context.Addressing.RelatesTo.TargetElement != null)
                    expectedOptions |= SignatureOptions.IncludeRelatesTo;

                if (envelope.Context.Addressing.ReplyTo != null && envelope.Context.Addressing.ReplyTo.TargetElement != null)
                    expectedOptions |= SignatureOptions.IncludeReplyTo;
                //
                // Check if the all the expected options are the present.
                //
                return ((expectedOptions & actualOptions) == expectedOptions);

            }
        }

        #endregion
    }
}
