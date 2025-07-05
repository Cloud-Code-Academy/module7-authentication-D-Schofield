/**
 * Password authentication not supported for external client apps
 * And disabled in the org by default
 * Therefore, separated the PW test to run on it's own. 
 * 
 * Setup: 
 * 1. External Client App Settings: enable 'Allow creation of connected apps'
 * 2. Create a legacy Connected App for PW Flow
 * 3. OAuth and OpenID Connect Settings: enable: 'Allow OAuth Username-Password Flows'
 * 
 * Documentation: 
 * Connected Apps - Summer '25 disabled by default
 * https://help.salesforce.com/s/articleView?id=xcloud.connected_app_overview.htm&type=5
 * Username-password flows blocked by default
 * https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_disable_username_password_flow.htm&type=5
 * Username-password flows for special scenarios
 * https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_username_password_flow.htm&type=5
 */

String clientId = 'legacyConnectedAppClientId';
String clientSecret = 'legacyConnectedAppClientSecret';

String username = 'username';
String password = 'password';
String securityToken = 'token;

System.debug('Testing Password Flow...');

try {
    String tokenUrl = 'https://destination-org-dev-ed.trailblaze.my.salesforce.com/services/oauth2/token';
    
    // Exact format from Salesforce docs - NO SCOPE
    String requestBody = 'grant_type=password' +
        '&client_id=' + EncodingUtil.urlEncode(clientId, 'UTF-8') +
        '&client_secret=' + EncodingUtil.urlEncode(clientSecret, 'UTF-8') +
        '&username=' + EncodingUtil.urlEncode(username, 'UTF-8') +
        '&password=' + EncodingUtil.urlEncode(password + securityToken, 'UTF-8');
    
    System.debug('requestBody: ' +requestBody);
    
    // Make HTTP request
    HttpRequest req = new HttpRequest();
    req.setEndpoint(tokenUrl);
    req.setMethod('POST');
    req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
    req.setBody(requestBody);
    req.setTimeout(60000);
    
    Http http = new Http();
    HttpResponse res = http.send(req);
    
    System.debug('Status Code: ' + res.getStatusCode());
    System.debug('Response Body: ' + res.getBody());
    
    if (res.getStatusCode() == 200) {
        System.debug('✅ SUCCESS: Password Flow works with exact implementation!');
        
        // Parse success response (expected format from docs)
        try {
            Map<String, Object> responseData = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
            // Extract values for additional testing
            String accessToken = (String) responseData.get('access_token');
            String instanceUrl = (String) responseData.get('instance_url');
            
            // Test getting org limits
            System.debug('Testing org limits retrieval...');
            Map<String, Object> limits = SFExternalCalloutWithToken.getLimits(accessToken, instanceUrl);
            System.debug('Org limits retrieved: ' + (limits.containsKey('error') ? '❌ FAILED' : '✅ SUCCESS'));
            
            // Test creating an account
            System.debug('Testing account creation...');
            String accountName = 'Password Test Account ' + DateTime.now().getTime();
            SFExternalCalloutWithToken.CreateAccountResult createAccountResult = SFExternalCalloutWithToken.createAccount(
                accountName,
                accessToken,
                instanceUrl
            );
            System.debug('Account creation: ' + (createAccountResult.isSuccess ? '✅ SUCCESS (ID: ' + createAccountResult.accountId + ')' : '❌ FAILED'));
            if (!createAccountResult.isSuccess) {
                System.debug('  - Error: ' + createAccountResult.errorMessage);
            }
            
            System.debug('=== ALL TESTS COMPLETE ===');
            System.debug('✅ Password Flow authentication: SUCCESS');
            System.debug('✅ Org limits retrieval: ' + (limits.containsKey('error') ? 'FAILED' : 'SUCCESS'));
            System.debug('✅ Account creation: ' + (createAccountResult.isSuccess ? 'SUCCESS' : 'FAILED'));
            
        } catch (Exception parseEx) {
            System.debug('Could not parse success response');
        }
    } else {
        System.debug('❌ FAILED: Password Flow failed');
        
        // Parse error response
        try {
            Map<String, Object> errorData = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
            System.debug('Error Type: ' + errorData.get('error'));
            System.debug('Error Description: ' + errorData.get('error_description'));            
        } catch (Exception parseEx) {
            System.debug('Could not parse error response');
        }
    }
    
} catch (Exception e) {
    System.debug('❌ EXCEPTION: ' + e.getMessage());
    System.debug('Stack: ' + e.getStackTraceString());
} 