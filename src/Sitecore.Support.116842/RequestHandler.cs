using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Sitecore.Diagnostics;
using Sitecore.ExperienceEditor.Speak.Server;
using Sitecore.ExperienceEditor.Speak.Server.Requests;
using Sitecore.ExperienceEditor.Speak.Server.Responses;
using Sitecore.Security.AntiCsrf;
using System.Web.Helpers;
using Sitecore.Web.Authentication;
using Newtonsoft.Json;
using System.Reflection;
using Sitecore.Reflection;
using Sitecore.Globalization;
using Sitecore.ExperienceEditor.Speak.Attributes;
using Sitecore;
using System.Web.SessionState;
using System.Xml;
using System.Xml.Linq;
using Sitecore.Configuration;


namespace Sitecore.Support.ExperienceEditor.Speak.Server
{
    


    public class RequestHandler :  IHttpHandler, IRequiresSessionState
    {
        private readonly List<AntiCsrfRule> rules = new List<AntiCsrfRule>();
        public bool IsReusable
        {
            get
            {
                return false;
            }
        }

        protected virtual void LoadConfiguration()
        {
            XmlNode configNode = Factory.GetConfigNode("AntiCsrf");
            if (configNode != null)
            {
                XElement xElement = XElement.Parse(configNode.OuterXml);
                foreach (XElement current in xElement.Descendants("rule"))
                {
                    this.LoadRule(current);
                }
            }
        }

        protected virtual void LoadRule(XElement rule)
        {
            if (rule == null)
            {
                return;
            }
            XElement xElement = rule.Element("urlPrefix");
            if (xElement == null || string.IsNullOrEmpty(xElement.Value))
            {
                return;
            }
            string urlPrefix = xElement.Value;
            XAttribute xAttribute = rule.Attribute("name");
            string ruleName = string.Empty;
            if (xAttribute != null)
            {
                ruleName = xAttribute.Value;
            }
            AntiCsrfRule antiCsrfRule = this.rules.Find((AntiCsrfRule r) => r.UrlPrefix == urlPrefix);
            if (antiCsrfRule == null)
            {
                antiCsrfRule = new AntiCsrfRule(urlPrefix, ruleName);
                this.rules.Add(antiCsrfRule);
            }
            this.InitializeRuleFilters(antiCsrfRule, rule);
        }

        protected virtual void InitializeRuleFilters(AntiCsrfRule csrfRule, XElement rule)
        {
            if (csrfRule == null || rule == null)
            {
                return;
            }
            foreach (XElement current in rule.Elements("ignore"))
            {
                XAttribute xAttribute = current.Attribute("contains");
                if (xAttribute != null && xAttribute.Value.Trim().Length > 0)
                {
                    csrfRule.AddFilter(new AntiCsrfUrlFilter(xAttribute.Value));
                }
                else
                {
                    xAttribute = current.Attribute("wildcard");
                    if (xAttribute != null && xAttribute.Value.Trim().Length > 0)
                    {
                        csrfRule.AddFilter(new AntiCsrfWildcardUrlFilter(xAttribute.Value));
                    }
                }
            }
        }
        public  void ProcessRequest(HttpContext context)
        {
            try
            {
                LoadConfiguration();
                Assert.ArgumentNotNull(context, "context");
                Assert.IsNotNull(context.Request, "Request is null");
                Assert.IsNotNull(context.Response, "Response is null");
                context.Response.ContentType = "application/json";
                context.Response.Write(Process(context));
            }
            catch (Exception ex)
            {
                Log.Error(string.Format("Error processing command url:{0} error:{1}", context.Request.RawUrl, ex), ex);
                context.Response.Write(JsonConvert.SerializeObject(new Response
                {
                    Error = true,
                    ErrorMessage = ClientHost.Globalization.Translate("A serious error occurred please contact the administrator")
                }));
            }
            finally
            {
                context.Response.Flush();
                context.Response.End();
            }
        }

        private readonly RequestArgsFactory requestArgsFactory = new RequestArgsFactory();

        private readonly RequestRepository requestRepository = new RequestRepository();

        private static Response GetErrorResponse(string errorMessage)
        {
            Response response = new Response();
            response.Error = true;
            response.ErrorMessage = errorMessage;
            response.PostScriptFunc = string.Empty;
            return response;
        }

        protected string Process(HttpContext context)
        {
            Assert.ArgumentNotNull(context, "context");
            Assert.IsNotNull(context.Request, "Request is null");
            Assert.IsNotNull(context.Response, "Response is null");
            RequestArgs args = this.requestArgsFactory.Create(context.Request);
            Assert.IsNotNull(args, string.Format("Could not retrieve request arguments from url:{0}", context.Request.RawUrl));
            Request request = this.requestRepository.Get(args);
            Assert.IsNotNull(request, string.Format("Could not retrieve request class for url:{0}", context.Request.RawUrl));
            bool flag = false;
            foreach (AntiCsrfRule current in rules)
            {
                if (current.FilterUrl(context.Request.RawUrl))
                {
                    flag = true;
                }
            }
            if (!flag)
            {
                AntiForgery.Validate();
            }

            if (!TicketManager.IsCurrentTicketValid())
            {
                string str = "User ticket is not valid";
                Log.Error(str, this);
                return JsonConvert.SerializeObject(GetErrorResponse(Translate.Text("An error occurred.")));
            }
            MethodInfo info = ReflectionUtil.GetMethod(request, "ProcessRequest", new object[0]);
            if (info.GetCustomAttributes(typeof(SitecoreAuthorizeAttribute), true).Any<object>())
            {
                SitecoreAuthorizeAttribute attribute = (SitecoreAuthorizeAttribute)info.GetCustomAttributes(typeof(SitecoreAuthorizeAttribute), true).First<object>();
                if ((attribute != null) && !attribute.IsAllowed())
                {
                    Log.Error(string.Format("User {0} does not have enough rights to run {1}. Roles that allow running this method: {2}.", Context.User.Name, (info.DeclaringType == null) ? info.Name : info.DeclaringType.FullName, attribute.Roles), this);
                    return JsonConvert.SerializeObject(GetErrorResponse(Translate.Text("An error occurred.")));
                }
            }
            if (info.GetCustomAttributes(typeof(HasItemPermissionsAttribute), true).Any<object>())
            {
                HasItemPermissionsAttribute attribute2 = (HasItemPermissionsAttribute)info.GetCustomAttributes(typeof(HasItemPermissionsAttribute), true).First<object>();
                if ((attribute2 != null) && !attribute2.IsAllowed())
                {
                    Log.Error(string.Format("User {0} does not have enough rights to item {1} {2}.", Context.User.Name, attribute2.Path, attribute2.Id), this);
                    return JsonConvert.SerializeObject(GetErrorResponse(Translate.Text("An error occurred.")));
                }
            }
            return HttpUtility.UrlDecode(JsonConvert.SerializeObject(ReflectionUtil.CallMethod(request, args.MethodName, new object[] { args })));
        }
    }
}