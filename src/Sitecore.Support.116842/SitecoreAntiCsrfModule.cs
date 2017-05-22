using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Sitecore.Support.Security.AntiCsrf
{
<<<<<<< HEAD
    public class SitecoreAntiCsrfModule : Sitecore.Security.AntiCsrf.SitecoreAntiCsrfModule
=======
    public class SitecoreAntiCsrfModule: Sitecore.Security.AntiCsrf.SitecoreAntiCsrfModule
>>>>>>> e9319a6b7b10c2e1c2832a5d23a7028262418609
    {
        internal void InvokeBaseLoadConfiguration()
        {
            base.LoadConfiguration();
        }
    }
}