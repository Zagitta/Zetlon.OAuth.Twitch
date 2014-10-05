using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Web;
using DotNetOpenAuth.AspNet.Clients;
using DotNetOpenAuth.Messaging;
using Newtonsoft.Json.Linq;

namespace Zetlon.OAuth.Twitch
{
    /// <summary>
    /// OAuth2 Client for Twitch
    /// See more details at https://github.com/justintv/Twitch-API/blob/master/authentication.md
    /// </summary>
    /// <example>
    /// OAuthWebSecurity.RegisterClient(new TwitchClient("ClientId", "ClientSecret", "channel_check_subscription"));
    /// </example>
    public class TwitchClient : OAuth2Client
    {
        private const string ApiUrl = "https://api.twitch.tv/kraken/";
        private const string Enduserauthlink = ApiUrl + "oauth2/authorize?response_type=code";
        private const string TokenLink = ApiUrl + "oauth2/token?&grant_type=authorization_code";
        private const string UserUrl = ApiUrl + "user/";
        private const string StateVar = "state";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _scopes;

        /// <summary>
        /// Dictionary containing user data keys that must be renamed to fit OAuth2Client naming
        /// </summary>
        private static readonly Dictionary<string, string> Replacements = new Dictionary<string, string>()
        {
            {"name", "username"},
            {"_id", "id"}
        }; 
        
        public TwitchClient(string clientId, string clientSecret, IEnumerable<string> scopes) : base("Twitch")
        {
            if (clientId == null) throw new ArgumentNullException("clientId");
            if (clientSecret == null) throw new ArgumentNullException("clientSecret");
            if (scopes == null) throw new ArgumentNullException("scopes");
            
            _clientId = clientId;
            _clientSecret = clientSecret;
            _scopes = CreateScopeString(scopes);
        }

        public TwitchClient(string clientId, string clientSecret, params string[] scopes)
            : this(clientId, clientSecret, (IEnumerable<string>) scopes){ }

        
        protected override Uri GetServiceLoginUrl(Uri returnUrl)
        {
            var builder = new UriBuilder(Enduserauthlink);

            builder.AppendQueryArgument("client_id", _clientId);

            //Removes the '?' at the start of the query string so TwitchState.DecodeTwitchCallback doesn't have to deal with it
            builder.AppendQueryArgument("state", returnUrl.Query.Substring(1));

            builder.AppendQueryArgument("redirect_uri", returnUrl.GetLeftPart(UriPartial.Path));

            builder.AppendQueryArgument("scope", _scopes);

            return builder.Uri;
        }

        protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
        {
            var b = new StringBuilder();
            
            b.Append(TokenLink);
            AppendDefaults(b, returnUrl);
            b.AppendFormat("&client_secret={0}", _clientSecret);
            b.AppendFormat("&code={0}", authorizationCode);
            
            using (var client = new WebClient())
            {
                SetHeaders(client);

                var response = client.UploadString(b.ToString(), "POST", "");

                var json = JObject.Parse(response);

                return json.GetValue("access_token").ToObject<string>();
            }
        }

        protected override IDictionary<string, string> GetUserData(string accessToken)
        {
            using (var client = new WebClient())
            {
                SetHeaders(client);

                var response = client.UploadString(UserUrl, "POST", "");

                var json = JObject.Parse(response);

                var dic = new Dictionary<string, string>();

                foreach (var pair in json)
                {
                    var name = Replacements.ContainsKey(pair.Key) ? Replacements[pair.Key] : pair.Key;
                    var value = pair.Value.ToString();

                    dic.Add(name, value);
                }

                return dic;
            }
        }

        /// <summary>
        /// Appends client id and return url to a string builder
        /// </summary>
        private void AppendDefaults(StringBuilder b, Uri returnUrl)
        {
            b.AppendFormat("&client_id={0}", _clientId);
            b.AppendFormat("&redirect_uri={0}", Uri.EscapeUriString(returnUrl.ToString()));
        }

        /// <summary>
        /// Sets the header of a WebClient instance to api version 3 and provides the client id to avoid getting rate limited.
        /// The auth token is also set if provided.
        /// </summary>
        private void SetHeaders(WebClient client, string token = null)
        {
            var headers = new WebHeaderCollection
            {
                {HttpRequestHeader.Accept, "application/vnd.twitchtv.v3+json"},
                {"Client-ID", _clientId}
            };

            if(!string.IsNullOrWhiteSpace(token))
                headers.Add(HttpRequestHeader.Authorization, string.Format("OAuth {0}", token));

            client.Headers = headers;
        }

        /// <summary>
        /// Returns a scope string formatted acording to twitch rules, ex: "user_read+channel_check_subscription"
        /// </summary>
        private static string CreateScopeString(IEnumerable<string> scopes)
        {
            //user_read scope is required as a minimum for GetUserData
            var set = new HashSet<string>(scopes, StringComparer.OrdinalIgnoreCase) { "user_read" };
            
            return string.Join(" ", set);
        }


        /// <summary>
        /// Converts the Twitch state parameter into a format understood by DotNetOpenAuth
        /// </summary>
        public static void DecodeCallback()
        {
            var context = HttpContext.Current;

            if (context == null)
                return;

            var request = context.Request;

            if(request == null)
                return;

            var state = request.QueryString[StateVar];

            if (string.IsNullOrWhiteSpace(state) || request.Url == null)
                return;

            var b = new UriBuilder(request.Url.GetLeftPart(UriPartial.Path))
            {
                Query = Uri.UnescapeDataString(state)
            };

            context.Response.Redirect(b.ToString(), true);
        }
    }
}
