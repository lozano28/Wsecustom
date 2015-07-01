using System;
using System.Xml;
using System.Web;
using System.Web.Services;
using System.Web.Services.Protocols;

using Microsoft.Web.Services3; 

[WebService(Namespace = "http://company.com/samples/wse/")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
[Policy("ServerPolicy")] // we define policy on service level, so each service method will be covered by it
public class Service : System.Web.Services.WebService // look, you don't need to inherit your service from some custom class
{
    /// <summary>
    /// Define settings custom SOAP header that will be used in almost every method.
    /// </summary>
    public BankAccountSettings settings;

    public Service ()
    {
    }

    [WebMethod, SoapHeader("settings")]
    public bool CheckAccountStatus(string accountNumber)
    {
        if (settings == null)
            throw new SoapException("Settings information has not been provided", new XmlQualifiedName("settings"));

        // do some processing here
        // for example purposes we just check
        // settings PinCode property for some hardcoded "1111" value
        return (settings.PinCode == "1111");
    }
    
}
