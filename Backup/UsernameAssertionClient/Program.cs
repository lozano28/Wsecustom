using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Text;

using Microsoft.Web.Services3;
using Microsoft.Web.Services3.Design;

using UsernameAssertionLibrary;

namespace UsernameAssertionClient
{
    class Program
    {
        static void Main(string[] args)
        {
            // create web service proxy
            // NOTE!!! When updating web reference in Visual Studio,
            // don't forget to change its base class to Microsoft.Web.Services3.WebServicesClientProtocol then
            WseSample.Service srv = new WseSample.Service();

            // create custom SOAP header and assign it to web service
            WseSample.BankAccountSettings settings = new WseSample.BankAccountSettings();
            settings.PinCode = "1111";
            srv.BankAccountSettingsValue = settings;

            // create custom policy assertion and assign it to proxy
            // for password we just use reversed username
            // it's important, because UsernameTokenManager on the service side applies the same logic
            // when looking for user password
            UsernameClientAssertion assert = new UsernameClientAssertion("admin", "nimda");

            // create policy
            Policy policy = new Policy();
            policy.Assertions.Add(assert);

            // and set it to web service
            srv.SetPolicy(policy);

            // invoke web service method
            bool valid = srv.CheckAccountStatus("123456");
            Debug.WriteLine(valid);
        }
    }
}
