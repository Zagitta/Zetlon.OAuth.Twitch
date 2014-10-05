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
    public class TwitchClient : OAuth2Client
    {
        private const string ApiUrl = "https://api.twitch.tv/kraken/";
        private const string Enduserauthlink = ApiUrl + "oauth2/authorize?response_type=code";
        private const string TokenLink = ApiUrl + "oauth2/token?&grant_type=authorization_code";
        private const string UserUrl = ApiUrl + "user/";
        private const string StateVar = "state";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _callbackUrl;
        private readonly string _scopes;

        /// <summary>
        /// Dictionary containing user data keys that must be renamed to fit OAuth2Client naming
        /// </summary>
        private static readonly Dictionary<string, string> Replacements = new Dictionary<string, string>()
        {
            {"name", "username"},
            {"_id", "id"}
        }; 
        /// <summary>
        /// Creates a new instance of the TwitchClient class.
        /// </summary>
        /// <param name="clientId">The client id provided by Twitch.</param>
        /// <param name="clientSecret">The client secret provided by Twitch.</param>
        /// <param name="callbackUrl">The exact callback url as specified on the application settings site on Twitch.</param>
        /// <param name="scopes">The scopes you want to request access to.</param>
        /// <example> 
        /// var helper = new UrlHelper();
        /// var returnUrl = helper.Action("ReturnUrl", "Account");
        /// OAuthWebSecurity.RegisterClient(new TwitchClient("ClientId", "ClientSecret", returnUrl, "channel_check_subscription"));
        /// </example>
        public TwitchClient(string clientId, string clientSecret, string callbackUrl, IEnumerable<string> scopes) : base("Twitch")
        {
            if (clientId == null) throw new ArgumentNullException("clientId");
            if (clientSecret == null) throw new ArgumentNullException("clientSecret");
            if (callbackUrl == null) throw new ArgumentNullException("callbackUrl");
            if (scopes == null) throw new ArgumentNullException("scopes");
            
            _clientId = clientId;
            _clientSecret = clientSecret;
            _callbackUrl = callbackUrl;

            //user_read scope is required as a minimum for GetUserData
            var set = new HashSet<string>(scopes, StringComparer.OrdinalIgnoreCase) { "user_read" };
            _scopes = string.Join(" ", set);
        }

        /// <summary>
        /// Creates a new instance of the TwitchClient class.
        /// </summary>
        /// <param name="clientId">The client id provided by Twitch.</param>
        /// <param name="clientSecret">The client secret provided by Twitch.</param>
        /// <param name="callbackUrl">The exact callback url as specified on the application settings site on Twitch.</param>
        /// <param name="scopes">The scopes you want to request access to.</param>
        public TwitchClient(string clientId, string clientSecret, string callbackUrl, params string[] scopes)
            : this(clientId, clientSecret, callbackUrl, (IEnumerable<string>) scopes){ }

        
        protected override Uri GetServiceLoginUrl(Uri returnUrl)
        {
            var builder = new UriBuilder(Enduserauthlink);

            builder.AppendQueryArgument("client_id", _clientId);
            //Removes the '?' at the start of the query string so TwitchState.DecodeTwitchCallback doesn't have to deal with it
            builder.AppendQueryArgument(StateVar, returnUrl.AbsoluteUri);
            builder.AppendQueryArgument("redirect_uri", _callbackUrl);
            builder.AppendQueryArgument("scope", _scopes);

            return builder.Uri;
        }

        protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
        {
            var b = new UriBuilder(TokenLink);
            b.AppendQueryArgument("client_id", _clientId);
            b.AppendQueryArgument("client_secret", _clientSecret);
            b.AppendQueryArgument("redirect_uri", _callbackUrl);
            b.AppendQueryArgument("code", authorizationCode);

            using (var client = new WebClient())
            {
                SetHeaders(client);

                var response = client.UploadString(b.Uri, "POST", "");

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
        /// Converts the Twitch state parameter into a format understood by DotNetOpenAuth.
        /// </summary>
        /// <param name="redirectUrl">The uri to redirect to.</param>
        /// <returns>True if the <see cref="redirectUrl"/> should be redirected to, otherwise false.</returns>
        public static bool DecodeCallback(out Uri redirectUrl)
        {
            redirectUrl = null;
            var context = HttpContext.Current;

            if (context == null)
                return false;

            var request = context.Request;

            if(request == null)
                return false;

            var state = request.QueryString[StateVar];

            if (string.IsNullOrWhiteSpace(state) || request.Url == null)
                return false;

            redirectUrl = new Uri(state);
            
            return true;
        }
    }
}
