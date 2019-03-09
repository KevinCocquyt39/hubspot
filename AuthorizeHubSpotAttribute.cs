namespace AcmeCorp.Web.Infrastructure.API.Filters
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security.Cryptography;
    using System.Text;
    using System.Web.Http.Controllers;
    using NLog;
    using ActionFilterAttribute = System.Web.Http.Filters.ActionFilterAttribute;

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class AuthorizeHubSpotAttribute : ActionFilterAttribute
    {
        // nlog logging
        private static readonly Logger Logger = LogManager.GetLogger("HubSpot");

        public override void OnActionExecuting(HttpActionContext filterContext)
        {
            Logger.Info("Start authorization of HubSpot Request Signature");

            var requestBody = GetHubSpotRequestBody(filterContext);
            Logger.Info($"HubSpot Request Body: {requestBody}");

            var hubSpotRequestSignature = GetHubSpotRequestSignature(filterContext);
            Logger.Info($"HubSpot Request Signature: {hubSpotRequestSignature}");

            var computedRequestSignature = GetSignatureWithSecretAndMethodAndUriAndBody(filterContext, requestBody);
            Logger.Info($"Computed Request Signature: {computedRequestSignature}");

            // config file setting
            if (Settings.HubSpot.UseSignatureCheck == false)
            {
                Logger.Info("Skip authorization of HubSpot Request Signature (by setting 'HubSpot.UseSignatureCheck')");
                return;
            }

            if (hubSpotRequestSignature != computedRequestSignature)
            {
                Logger.Info("Compare HubSpot Request Signature with Computed Request Signature = INVALID");

                filterContext.Response = filterContext.Request.CreateErrorResponse(
                    HttpStatusCode.Unauthorized,
                    "Invalid request signature.");

                return;
            }

            Logger.Info("Compare HubSpot Request Signature with Computed Request Signature = SUCCESS");
            base.OnActionExecuting(filterContext);
        }

        private static string GetHubSpotRequestSignature(HttpActionContext filterContext)
        {
            if (filterContext.Request.Headers.TryGetValues("X-HubSpot-Signature", out var hubSpotRequestSignatureList))
            {
                return hubSpotRequestSignatureList == null ? string.Empty : hubSpotRequestSignatureList.FirstOrDefault();
            }

            return string.Empty;
        }

        private static string GetHubSpotRequestUri(HttpActionContext filterContext)
        {
            var absoluteUri = filterContext.Request.RequestUri.AbsoluteUri;

            // in case of https offloading (eg. nginx reverse proxy)
            if (filterContext.Request.Headers.TryGetValues("X-Forwarded-Proto", out var forwardedProtoList) == false)
            {
                return absoluteUri;
            }

            if (forwardedProtoList == null)
            {
                return absoluteUri;
            }

            var proto = forwardedProtoList.FirstOrDefault();
            if (proto == null)
            {
                return absoluteUri;
            }

            return string.Equals(proto, "https", StringComparison.OrdinalIgnoreCase)
                       ? absoluteUri.Replace("http://", "https://")
                       : absoluteUri;
        }

        private static string GetHubSpotRequestBody(HttpActionContext filterContext)
        {
            // because the request content is buffered, it could be that the request content is empty when reading it as a string
            // to rewind the buffer, set position to zero (https://stackoverflow.com/questions/18340487/web-api-action-filter-content-cant-be-read)
            var reqStream = filterContext.Request.Content.ReadAsStreamAsync().Result;
            if (reqStream.CanSeek)
            {
                reqStream.Position = 0;
            }

            return filterContext.Request.Content.ReadAsStringAsync().Result;
        }

        /// <summary>
        /// Gets the signature with secret and body (used for webhooks).
        /// https://developers.hubspot.com/docs/methods/webhooks/webhooks-overview#user-content-security
        /// </summary>
        /// <param name="filterContext">The filter context.</param>
        /// <param name="requestBody">The request body.</param>
        /// <returns>The signature.</returns>
        private static string GetSignatureWithSecretAndBody(HttpActionContext filterContext, string requestBody)
        {
            var secret = Settings.HubSpot.SyncAppKey;

            return EncryptToSHA256($"{secret}{requestBody}");
        }

        /// <summary>
        /// Gets the signature with secret and method and URI (used for other requests).
        /// https://developers.hubspot.com/docs/faq/validating-requests-from-hubspot
        /// </summary>
        /// <param name="filterContext">The filter context.</param>
        /// <returns>The signature.</returns>
        private static string GetSignatureWithSecretAndMethodAndUri(HttpActionContext filterContext)
        {
            var secret = Settings.HubSpot.SyncAppKey;

            var method = filterContext.Request.Method.ToString();
            Logger.Info($"HubSpot Request Method: {method}");

            var uri = GetHubSpotRequestUri(filterContext);
            Logger.Info($"HubSpot Request URI: {uri}");

            return EncryptToSHA256($"{secret}{method}{uri}");
        }

        /// <summary>
        /// Gets the signature with secret and method and URI and body (used for workflows).
        /// https://developers.hubspot.com/docs/methods/crm-extensions/crm-extensions-overview#request-signatures
        /// </summary>
        /// <param name="filterContext">The filter context.</param>
        /// <param name="requestBody">The request body.</param>
        /// <returns>The signature.</returns>
        private static string GetSignatureWithSecretAndMethodAndUriAndBody(HttpActionContext filterContext, string requestBody)
        {
            var secret = Settings.HubSpot.SyncAppKey;

            var method = filterContext.Request.Method.ToString();
            Logger.Info($"HubSpot Request Method: {method}");

            var uri = GetHubSpotRequestUri(filterContext);
            Logger.Info($"HubSpot Request URI: {uri}");

            return EncryptToSHA256($"{secret}{method}{uri}{requestBody}");
        }

        private static string EncryptToSHA256(string value)
        {
            using (var hashMethod = SHA256.Create())
            {
                var hashValue = hashMethod.ComputeHash(Encoding.UTF8.GetBytes(value));

                var hash = new StringBuilder();
                foreach (var byteValue in hashValue)
                {
                    hash.Append($"{byteValue:x2}");
                }

                return hash.ToString();
            }
        }
    }
}