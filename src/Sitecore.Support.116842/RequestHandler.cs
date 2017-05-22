using System.Linq;
using System.Web;
using Sitecore.Diagnostics;
using Sitecore.ExperienceEditor.Speak.Server;
using Sitecore.ExperienceEditor.Speak.Server.Requests;
using Sitecore.ExperienceEditor.Speak.Server.Responses;
using Sitecore.Web.Authentication;
using Newtonsoft.Json;
using System.Reflection;
using System.Web.Helpers;
using Sitecore.Reflection;
using Sitecore.Globalization;
using Sitecore.ExperienceEditor.Speak.Attributes;
using Sitecore.Security.AntiCsrf;

namespace Sitecore.Support.ExperienceEditor.Speak.Server
{
    public class RequestHandler : Sitecore.ExperienceEditor.Speak.Server.RequestHandler
    {
        private readonly RequestArgsFactory requestArgsFactory;
        private readonly RequestRepository requestRepository;

        public RequestHandler()
        {
            this.requestArgsFactory = new RequestArgsFactory();
            this.requestRepository = new RequestRepository();
        }

        protected override string Process(HttpContext context)
        {
            Assert.ArgumentNotNull(context, "context");
            Assert.IsNotNull(context.Request, "Request is null");
            Assert.IsNotNull(context.Response, "Response is null");
            RequestArgs args = this.requestArgsFactory.Create(context.Request);
            Assert.IsNotNull(args, $"Could not retrieve request arguments from url:{context.Request.RawUrl}");
            Request request = this.requestRepository.Get(args);
            Assert.IsNotNull(request, $"Could not retrieve request class for url:{context.Request.RawUrl}");
            Sitecore.Support.Security.AntiCsrf.SitecoreAntiCsrfModule sitecoreAntiCsrfModule = new Sitecore.Support.Security.AntiCsrf.SitecoreAntiCsrfModule();
            sitecoreAntiCsrfModule.InvokeBaseLoadConfiguration();
            bool flag = false;
            foreach (AntiCsrfRule rule in sitecoreAntiCsrfModule.Rules)
            {
                if (rule.FilterUrl(context.Request.RawUrl))
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
                string message = "User ticket is not valid";
                Log.Error(message, this);
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
                    Log.Error($"User {Context.User.Name} does not have enough rights to item {attribute2.Path} {attribute2.Id}.", this);
                    return JsonConvert.SerializeObject(GetErrorResponse(Translate.Text("An error occurred.")));
                }
            }
            return HttpUtility.UrlDecode(JsonConvert.SerializeObject(ReflectionUtil.CallMethod(request, args.MethodName, new object[] { args })));
        }

        private static Response GetErrorResponse(string errorMessage) =>
            new Response
            {
                Error = true,
                ErrorMessage = errorMessage,
                PostScriptFunc = string.Empty
            };
    }
}