/**
 * Service class to handle OAuth 2.0 authentication with Salesforce
 * STUDENT VERSION - Complete the method implementations
 */
public with sharing class SFAuthenticationManager {
	// Endpoint for token requests
	private static final String TOKEN_ENDPOINT = '/services/oauth2/token';
	private static final String AUTHORIZE_ENDPOINT = '/services/oauth2/authorize';
	private static final String PKCE_GENERATOR_ENDPOINT = '/services/oauth2/pkce/generator';

	// Configuration values
	// client id and secret for the source org
	public static final String DEFAULT_CLIENT_ID = 'clientId';
	public static final String DEFAULT_CLIENT_SECRET = 'clientSecret';

	// login url for the destination org (where the Connected App is configured)
	public static final String DEFAULT_LOGIN_URL = 'https://cunning-shark-r0knl5-dev-ed.trailblaze.my.salesforce.com';

	// redirect url for the source org (where the Experience Cloud site is)
	public static final String DEFAULT_REDIRECT_URL = 'https://cunning-goat-nc9qj8-dev-ed.trailblaze.my.site.com/callback';
	
	// Logging configuration
	private static final String LOGGER_TAG = 'SFAuthManager';

	/**
	 * Central method to make OAuth token requests
	 * @param params Map of parameters to include in the request
	 * @param tokenUrl The full URL to the token endpoint
	 * @return Authentication response with token details or error
	 */
	private static AuthResponse makeTokenRequest(Map<String, String> params, String tokenUrl) {
		AuthResponse authResponse = new AuthResponse();

		// Guard clauses for input validation
		if (params == null || params.isEmpty()) {
			Logger.warn('makeTokenRequest called with null or empty parameters map')
				.addTag(LOGGER_TAG);
			Logger.saveLog();
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Parameters map cannot be null or empty';
			return authResponse;
		}

		if (String.isBlank(tokenUrl)) {
			Logger.warn('makeTokenRequest called with blank token URL')
				.addTag(LOGGER_TAG);
			Logger.saveLog();
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Token URL cannot be blank';
			return authResponse;
		}

		try {
			// Create HTTP request
			HttpRequest req = new HttpRequest();
			req.setEndpoint(tokenUrl);
			req.setMethod('POST');
			req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
			req.setTimeout(60000);

			// Convert parameters to URL encoded string
			String requestBody = buildUrlEncodedString(params);
			req.setBody(requestBody);

			// Send the request
			Http http = new Http();
			HttpResponse res = http.send(req);

			// Parse response
			if (res.getStatusCode() == 200) {
				// Success response
				Map<String, Object> responseData = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
				authResponse.isSuccess = true;
				authResponse.accessToken = (String) responseData.get('access_token');
				authResponse.refreshToken = (String) responseData.get('refresh_token');
				authResponse.instanceUrl = (String) responseData.get('instance_url');
				authResponse.tokenType = (String) responseData.get('token_type');
				
				// Handle expires_in which could be String or Integer
				Object expiresInObj = responseData.get('expires_in');
				if (expiresInObj instanceof String) {
					authResponse.expiresIn = Integer.valueOf((String) expiresInObj);
				} else if (expiresInObj instanceof Integer) {
					authResponse.expiresIn = (Integer) expiresInObj;
				}
				
				Logger.info('OAuth token request successful')
					.addTag(LOGGER_TAG);
				Logger.saveLog();
			} else {
				// Error response
				authResponse.isSuccess = false;
				authResponse.errorMessage = 'HTTP ' + res.getStatusCode() + ': ' + res.getStatus();
				
				// Try to parse error details from response body
				try {
					Map<String, Object> errorData = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
					authResponse.errorDetails = (String) errorData.get('error_description');
					if (String.isBlank(authResponse.errorDetails)) {
						authResponse.errorDetails = (String) errorData.get('error');
					}
				} catch (Exception parseEx) {
					authResponse.errorDetails = res.getBody();
				}
				
				Logger.error('OAuth token request failed')
					.addTag(LOGGER_TAG);
				Logger.saveLog();
			}
		} catch (Exception e) {
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Exception during token request: ' + e.getMessage();
			authResponse.errorDetails = e.getStackTraceString();
			
			Logger.error('Exception during OAuth token request', e)
				.addTag(LOGGER_TAG);
			Logger.saveLog();
		}

		return authResponse;
	}

	/**
	 * Utility method to build URL encoded string from parameters map
	 * @param params Map of parameters to encode
	 * @return URL encoded parameter string
	 */
	private static String buildUrlEncodedString(Map<String, String> params) {
		List<String> paramList = new List<String>();
		for (String key : params.keySet()) {
			String value = params.get(key);
			if (String.isNotBlank(value)) {
				paramList.add(EncodingUtil.urlEncode(key, 'UTF-8') + '=' + EncodingUtil.urlEncode(value, 'UTF-8'));
			}
		}
		return String.join(paramList, '&');
	}

	/**
	 * Authenticate using username and password flow (grant_type=password)
	 * @param username Username for the org
	 * @param password Password + Security Token
	 * @param securityToken Security Token
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithPassword(
		String username,
		String password,
		String securityToken
	) {
		// Guard clauses for input validation
		if (String.isBlank(username)) {
			Logger.warn('authenticateWithPassword called with blank username')
				.addTag(LOGGER_TAG);
			Logger.saveLog();
			AuthResponse authResponse = new AuthResponse();
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Username cannot be blank';
			return authResponse;
		}

		if (String.isBlank(password)) {
			Logger.warn('authenticateWithPassword called with blank password')
				.addTag(LOGGER_TAG);
			Logger.saveLog();
			AuthResponse authResponse = new AuthResponse();
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Password cannot be blank';
			return authResponse;
		}

		// Prepare parameters map
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'password',
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET,
			'username' => username,
			'password' => password + (String.isBlank(securityToken) ? '' : securityToken)
		};

		// Build token URL and call makeTokenRequest
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		Logger.info('Attempting password flow authentication')
			.addTag(LOGGER_TAG);
		Logger.saveLog();
		return makeTokenRequest(params, tokenUrl);
	}

	/**
	 * Authenticate using client credentials flow (grant_type=client_credentials)
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithClientCredentials() {
		// Prepare parameters map
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'client_credentials',
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET
		};

		// Build token URL and call makeTokenRequest
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		Logger.info('Attempting client credentials flow authentication')
			.addTag(LOGGER_TAG);
		Logger.saveLog();
		return makeTokenRequest(params, tokenUrl);
	}

	/**
	 * JWT Bearer Token Flow authentication
	 * @param username Username for the org
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithJWT(String username) {
		AuthResponse authResponse = new AuthResponse();

		// Guard clause for input validation
		if (String.isBlank(username)) {
			Logger.warn('authenticateWithJWT called with blank username')
				.addTag(LOGGER_TAG);
			Logger.saveLog();
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Username cannot be blank';
			return authResponse;
		}

		try {
			// Create JWT using Auth.JWT class
			Auth.JWT jwt = new Auth.JWT();
			jwt.setSub(username);
			jwt.setAud(DEFAULT_LOGIN_URL);
			jwt.setIss(DEFAULT_CLIENT_ID);

			// Create JWS (JSON Web Signature) with the JWT
			// 'jwtsource' should be the name of your certificate in Salesforce
			Auth.JWS jws = new Auth.JWS(jwt, 'jwtsource');

			// Get the compact serialization (token string)
			String token = jws.getCompactSerialization();
			String tokenEndpoint = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;

			// Create JWTBearerTokenExchange and get access token
			Auth.JWTBearerTokenExchange bearer = new Auth.JWTBearerTokenExchange(tokenEndpoint, jws);
			String accessToken = bearer.getAccessToken();

			// Build successful response
			authResponse.isSuccess = true;
			authResponse.accessToken = accessToken;
			authResponse.instanceUrl = DEFAULT_LOGIN_URL;
			authResponse.tokenType = 'Bearer';
			
			Logger.info('JWT authentication successful')
				.addTag(LOGGER_TAG);
			Logger.saveLog();

		} catch (Exception e) {
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'JWT authentication failed: ' + e.getMessage();
			authResponse.errorDetails = e.getStackTraceString();
			
			Logger.error('JWT authentication failed', e)
				.addTag(LOGGER_TAG);
			Logger.saveLog();
		}

		return authResponse;
	}

	/**
	 * Generate the authorization URL for Web Server Flow
	 * @param state Optional state parameter for CSRF protection
	 * @return Full authorization URL
	 */
	@AuraEnabled
	public static String generateAuthorizationUrl(String state) {
		// Build base authorization URL
		String authUrl = DEFAULT_LOGIN_URL + AUTHORIZE_ENDPOINT;
		
		// Build parameters
		List<String> params = new List<String>{
			'response_type=' + EncodingUtil.urlEncode('code', 'UTF-8'),
			'client_id=' + EncodingUtil.urlEncode(DEFAULT_CLIENT_ID, 'UTF-8'),
			'redirect_uri=' + EncodingUtil.urlEncode(DEFAULT_REDIRECT_URL, 'UTF-8')
		};

		// Add state parameter if provided
		if (String.isNotBlank(state)) {
			params.add('state=' + EncodingUtil.urlEncode(state, 'UTF-8'));
		}

		// Combine URL with parameters
		return authUrl + '?' + String.join(params, '&');
	}

	/**
	 * Generate PKCE data for OAuth 2.0 authorization
	 * @return PkceResponse containing code verifier and challenge
	 */
	@AuraEnabled
	public static PkceResponse generatePkceData() {
		PkceResponse pkceResponse = new PkceResponse();

		try {
			// Create HTTP request to PKCE generator endpoint
			HttpRequest req = new HttpRequest();
			req.setEndpoint(DEFAULT_LOGIN_URL + PKCE_GENERATOR_ENDPOINT);
			req.setMethod('GET');
			req.setHeader('Content-Type', 'application/json');
			req.setTimeout(60000);

			// Send request
			Http http = new Http();
			HttpResponse res = http.send(req);

			if (res.getStatusCode() == 200) {
				// Parse response for PKCE data
				Map<String, Object> responseData = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
				
				pkceResponse.isSuccess = true;
				pkceResponse.codeVerifier = (String) responseData.get('code_verifier');
				pkceResponse.codeChallenge = (String) responseData.get('code_challenge');
				pkceResponse.codeChallengeMethod = (String) responseData.get('code_challenge_method');
				
				Logger.info('PKCE data generated successfully')
					.addTag(LOGGER_TAG);
			Logger.saveLog();
			} else {
				pkceResponse.isSuccess = false;
				pkceResponse.errorMessage = 'Failed to generate PKCE data: HTTP ' + res.getStatusCode() + ' ' + res.getStatus();
				
				// Try to parse error details from response body
				try {
					Map<String, Object> errorData = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
					pkceResponse.errorDetails = (String) errorData.get('error_description');
					if (String.isBlank(pkceResponse.errorDetails)) {
						pkceResponse.errorDetails = (String) errorData.get('error');
					}
				} catch (Exception parseEx) {
					pkceResponse.errorDetails = res.getBody();
				}
			}
		} catch (Exception e) {
			pkceResponse.isSuccess = false;
			pkceResponse.errorMessage = 'Exception during PKCE generation: ' + e.getMessage();
			pkceResponse.errorDetails = e.getStackTraceString();
		}

		return pkceResponse;
	}

	/**
	 * Generate authorization URL with PKCE support
	 * @param usePkce Whether to include PKCE parameters
	 * @param codeChallenge Code challenge from PKCE generation
	 * @param codeChallengeMethod Code challenge method from PKCE generation
	 * @return Full authorization URL with PKCE parameters if requested
	 */
	@AuraEnabled
	public static String generateAuthorizationUrlWithPkce(
		Boolean usePkce,
		String codeChallenge,
		String codeChallengeMethod
	) {
		// Build base authorization URL
		String authUrl = DEFAULT_LOGIN_URL + AUTHORIZE_ENDPOINT;
		
		// Build base parameters
		List<String> params = new List<String>{
			'response_type=' + EncodingUtil.urlEncode('code', 'UTF-8'),
			'client_id=' + EncodingUtil.urlEncode(DEFAULT_CLIENT_ID, 'UTF-8'),
			'redirect_uri=' + EncodingUtil.urlEncode(DEFAULT_REDIRECT_URL, 'UTF-8')
		};

		// Add PKCE parameters if requested
		if (usePkce == true && String.isNotBlank(codeChallenge) && String.isNotBlank(codeChallengeMethod)) {
			params.add('code_challenge=' + EncodingUtil.urlEncode(codeChallenge, 'UTF-8'));
			params.add('code_challenge_method=' + EncodingUtil.urlEncode(codeChallengeMethod, 'UTF-8'));
		}

		// Combine URL with parameters
		return authUrl + '?' + String.join(params, '&');
	}

	/**
	 * Exchange authorization code for access token (grant_type=authorization_code)
	 * @param code Authorization code received from the redirect
	 * @return Authentication response with token details or error
	 */
	@AuraEnabled
	public static AuthResponse exchangeCodeForToken(String code) {
		// Guard clause for input validation
		if (String.isBlank(code)) {
			AuthResponse authResponse = new AuthResponse();
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Authorization code cannot be blank';
			return authResponse;
		}

		// Prepare parameters map
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'authorization_code',
			'code' => code,
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET,
			'redirect_uri' => DEFAULT_REDIRECT_URL
		};

		// Build token URL and call makeTokenRequest
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		return makeTokenRequest(params, tokenUrl);
	}

	/**
	 * Exchange authorization code for access token with PKCE support
	 * @param code Authorization code received from the redirect
	 * @param codeVerifier Code verifier for PKCE
	 * @return Authentication response with token details or error
	 */
	@AuraEnabled
	public static AuthResponse exchangeCodeForTokenWithPkce(String code, String codeVerifier) {
		// Guard clause for input validation
		if (String.isBlank(code)) {
			AuthResponse authResponse = new AuthResponse();
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Authorization code cannot be blank';
			return authResponse;
		}

		// Prepare parameters map like exchangeCodeForToken
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'authorization_code',
			'code' => code,
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET,
			'redirect_uri' => DEFAULT_REDIRECT_URL
		};

		// Add code_verifier parameter if provided
		if (String.isNotBlank(codeVerifier)) {
			params.put('code_verifier', codeVerifier);
		}

		// Build token URL and call makeTokenRequest
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		return makeTokenRequest(params, tokenUrl);
	}

	/**
	 * Refresh an existing access token using a refresh token
	 * Extra Credit: Implement this method
	 * @param refreshToken The refresh token from a previous authentication
	 * @return Authentication response with new token details or error
	 */
	public static AuthResponse refreshToken(String refreshToken) {
		// Guard clause for input validation
		if (String.isBlank(refreshToken)) {
			AuthResponse authResponse = new AuthResponse();
			authResponse.isSuccess = false;
			authResponse.errorMessage = 'Refresh token cannot be blank';
			return authResponse;
		}

		// Prepare parameters map
		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'refresh_token',
			'refresh_token' => refreshToken,
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET
		};

		// Build token URL and call makeTokenRequest
		String tokenUrl = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;
		return makeTokenRequest(params, tokenUrl);
	}

	/**
	 * Class to encapsulate authentication response
	 */
	public class AuthResponse {
		@AuraEnabled
		public Boolean isSuccess;
		@AuraEnabled
		public String accessToken;
		@AuraEnabled
		public String refreshToken;
		@AuraEnabled
		public String instanceUrl;
		@AuraEnabled
		public String tokenType;
		@AuraEnabled
		public Integer expiresIn;
		@AuraEnabled
		public String errorMessage;
		@AuraEnabled
		public String errorDetails;
	}

	/**
	 * Class to encapsulate PKCE response
	 */
	public class PkceResponse {
		@AuraEnabled
		public Boolean isSuccess;
		@AuraEnabled
		public String codeVerifier;
		@AuraEnabled
		public String codeChallenge;
		@AuraEnabled
		public String codeChallengeMethod;
		@AuraEnabled
		public String errorMessage;
		@AuraEnabled
		public String errorDetails;
	}
}
