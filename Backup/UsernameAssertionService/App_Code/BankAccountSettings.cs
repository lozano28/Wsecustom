using System;
using System.Data;
using System.Configuration;
using System.Web.Services.Protocols;

/// <summary>
/// BankAccountSettings represents a custom SOAP header that holds the contextual information about customer account.
/// </summary>
public class BankAccountSettings : UsernameAssertionLibrary.SecureSoapHeader
{
    public string PinCode;

    public BankAccountSettings()
    {
    }
}
