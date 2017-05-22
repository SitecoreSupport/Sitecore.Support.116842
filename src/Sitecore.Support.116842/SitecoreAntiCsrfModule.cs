using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Sitecore.Support.Security.AntiCsrf
{
    public class SitecoreAntiCsrfModule : Sitecore.Security.AntiCsrf.SitecoreAntiCsrfModule
    {
        internal void InvokeBaseLoadConfiguration()
        {
            base.LoadConfiguration();
        }
    }
}