<?php

/*

wp_oauth_test_auth_flow.php

Description : Simple PHP test to obtain oauth_access_token and oauth_access_token_secret from a Wordpress with WP-API and WP-OAuth plugins (and WP-CLI for OAuth consumer/app creation, for now) installed.

Author      : @kosso
Date        : Oct 29, 2014

See down below for the actual tests... 

(I should probably split these files up, but this is down and dirty to try and keep thing verbose and simple.)

*/

class OAuthWP
{

    function OAuthWP($config)
    {
        $this->key = $config['key'];
        $this->secret = $config['secret'];
     	$this->uri_request = $config['uri_request'];
     	$this->uri_authorize = $config['uri_authorize'];
     	$this->uri_access = $config['uri_access'];           
    }
    function getAccessToken($oauth_token, $oauth_verifier)
    {
        // Default params
        $params = array(
            "oauth_version" => "1.0",
            "oauth_nonce" => time(),
            "oauth_timestamp" => time(),
            "oauth_consumer_key" => $this->key,
            "oauth_signature_method" => "HMAC-SHA1",
            "oauth_token" => $oauth_token,
            "oauth_verifier" => $oauth_verifier
         );

        $request_method = 'POST';

     	// ## BUILD OAUTH SIGNATURE

        // Encode params keys, values, join and then sort.
        $keys = $this->_urlencode_rfc3986(array_keys($params));
        $values = $this->_urlencode_rfc3986(array_values($params));
        $params = array_combine($keys, $values);
        uksort($params, 'strcmp');

        // Convert params to string 
        foreach ($params as $k => $v) {$pairs[] = urlencode($k).'='.urlencode($v);}
        $concatenatedParams = implode('&', $pairs);
        $concatenatedParams = str_replace('=', '%3D', $concatenatedParams);
        $concatenatedParams = str_replace('&', '%26', $concatenatedParams);

        // Form base string (first key)
        $baseString= $request_method."&".urlencode($this->uri_access)."&".$concatenatedParams;

        // Form secret (second key)
        $secret = urlencode($this->secret)."&";
        // Make signature and append to params
        $params['oauth_signature'] = rawurlencode(base64_encode(hash_hmac('sha1', $baseString, $secret, TRUE)));
        
        // Re-sort params
        uksort($params, 'strcmp');

        // Build HTTP Authenticated Request Headers  (not used yet)
        $post_headers = $this->buildAuthorizationHeader($params);

        // Convert params to string 
        foreach ($params as $k => $v) {$urlPairs[] = $k."=".$v;}
        $concatenatedUrlParams = implode('&', $urlPairs);

        // Form the final url
        $url = $this->uri_access."?".$concatenatedUrlParams;

        // Send to cURL
        $access_tokens = $this->_http($url, $concatenatedUrlParams, $post_headers); 
        
        // Extract the values from the query paam
       	parse_str($access_tokens, $output);

       	return $output;

    }
    function getRequestToken()
    {
        // Default params
        $params = array(
            "oauth_version" => "1.0",
            "oauth_nonce" => time(),
            "oauth_timestamp" => time(),
            "oauth_consumer_key" => $this->key,
            "oauth_signature_method" => "HMAC-SHA1",
            "oauth_callback" => "http://microdio.com/test/oauth/test.php"
         );

        $request_method = 'POST';

     	// ## BUILD OAUTH SIGNATURE
        
        // Encode params keys, values, join and then sort.
        $keys = $this->_urlencode_rfc3986(array_keys($params));
        $values = $this->_urlencode_rfc3986(array_values($params));
        $params = array_combine($keys, $values);
        uksort($params, 'strcmp');

        // Convert params to string 
        foreach ($params as $k => $v) {$pairs[] = urlencode($k).'='.urlencode($v);}
        $concatenatedParams = implode('&', $pairs);
        $concatenatedParams = str_replace('=', '%3D', $concatenatedParams);
        $concatenatedParams = str_replace('&', '%26', $concatenatedParams);

        // Form base string (first key)
        $baseString= $request_method."&".urlencode($this->uri_request)."&".$concatenatedParams;
        // Form secret (second key)
        $secret = urlencode($this->secret)."&";
        // Make signature and append to params
        $params['oauth_signature'] = rawurlencode(base64_encode(hash_hmac('sha1', $baseString, $secret, TRUE)));
        
        // Re-sort params
        uksort($params, 'strcmp');

        // Build HTTP Authenticated Request Headers  (not used yet)
        $post_headers = $this->buildAuthorizationHeader($params);

        // convert params to string 
        foreach ($params as $k => $v) {$urlPairs[] = $k."=".$v;}
        $concatenatedUrlParams = implode('&', $urlPairs);

        // form url
        $url = $this->uri_request."?".$concatenatedUrlParams;

        // Send to cURL
        return $this->_http($url, $concatenatedUrlParams, $post_headers); 

    }

    function _http($url, $post_data = null, $post_headers = null)
    {       
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

        if(isset($post_data))
        {
        	//$header[] = 'Content-Type: application/x-www-form-urlencoded';

			if(isset($post_headers))
        	{
        		// array_push(array, var)
        		//curl_setopt($ch, CURLOPT_HTTPHEADER,     $header);
            	//curl_setopt($ch, CURLOPT_POST,        true);
            	$header[] = $post_headers;
        	}        	

        	// echo '<hr>setting post header: ';
        	// print_r($post_headers);
        	// echo "\n\n";

        	// worked with this too.... 
        	curl_setopt($ch, CURLOPT_HTTPHEADER, $post_headers);

            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, urlencode($post_data));

            //if(isset($post_headers))
        	//{
        		//$header[]         = 'Content-Type: application/x-www-form-urlencoded';
        		//curl_setopt($ch, CURLOPT_HTTPHEADER,     $header);
            	//curl_setopt($ch, CURLOPT_POST,        true);
        	//}
        }

        $response = curl_exec($ch);
        $this->http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->last_api_call = $url;
        curl_close($ch);

        return $response;
    }

    function _urlencode_rfc3986($input)
    {
        if (is_array($input)) {
            return array_map(array('OAuthWP', '_urlencode_rfc3986'), $input);
        }
        else if (is_scalar($input)) {
            return str_replace('+',' ',str_replace('%7E', '~', rawurlencode($input)));
        }
        else{
            return '';
        }
    }

    private function buildAuthorizationHeader($oauth){
            $r = 'Authorization: OAuth ';
            $values = array();
            foreach($oauth as $key => $value){
                    $values[] = $key . '="' . rawurlencode($value) . '"';
            }
            $r .= implode(', ', $values);
            return $r;
    }
    

}

echo '<pre>';

/*
    // Test OAuth connection.. (to WordPress).

    First, a 'consumer' (app) needs to be created on the server... 

    Using WP-CLI: (with WP-OAuth installed too)

    wp --path=/path/to/the/wordpress/webroot oauth1 add --name="Your App Name" --description="An OAuth client app for Wordpress via WP-API!"

    outputs:

    ID: 123456
    Key: someKeyForYourApp
    Secret: xxxxxxxxxxxxAsecretKeyxxxxxxxxxxxxxxxxxxx

    Use this information in the $oauth_config below... 

*/

// Edit the config to your requirements.
$oauth_config = array(
				'key' => 'someKeyForYourApp', 
				'secret'=>'xxxxxxxxxxxxAsecretKeyxxxxxxxxxxxxxxxxxxx',
                /* TODO: These should actually be 'discovered' from the /wp-json JSON in /authentication->oauth1['request|authorize|access'] ... */
				'uri_request'=> 'http://yourwordpressdomain.com/oauth1/request',
				'uri_authorize'=> 'http://yourwordpressdomain.com/oauth1/authorize',
				'uri_access'=> 'http://yourwordpressdomain.com/oauth1/access'
			);


$callback_protocol = 'http';
if(isset($_SERVER['HTTPS'])){ $callback_protocol = 'https'; }

// Set the OAuth callback to this script's url, no matter where it's run from.
$oauth_config['oauth_callback'] = $callback_protocol.'://'.$_SERVER['HTTP_HOST'].'/'.$_SERVER['SCRIPT_NAME'];


$auth = new OAuthWP($oauth_config);

// Hit after the oauth_callback, after request token generation. (Also added check to make sure we're coming back from the OAuth server host)
if(isset( $_REQUEST['oauth_token'] ) && isset( $_REQUEST['oauth_verifier'] ) && parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) == parse_url($oauth_config['uri_request'], PHP_URL_HOST)  ){
	
    // generate access tokens param string (format: oauth_token=1234567890QWERTYUIOP&oauth_token_secret=xxxxxxxxxxxxxxxxxxxxxxxxxx)
	$access_tokens = $auth->getAccessToken($_REQUEST['oauth_token'], $_REQUEST['oauth_verifier']);

	echo '<h3>Success! Here are your Access Tokens :</h3>';
	print_r($access_tokens);

	exit;

}

// Start OAuth authorisation by obtaining a request token and generating a link to the OAuth server, with a callback here ...
echo '<a href="'.$oauth_config['uri_authorize'].'?'.$auth->getRequestToken().'&oauth_callback='.urlencode($oauth_config['oauth_callback']).'">AUTHORIZE THIS APP</a>';


echo '</pre>';


?>
