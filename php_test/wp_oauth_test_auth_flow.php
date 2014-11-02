<?php

/*

wp_oauth_test_auth_flow.php

Description : Simple PHP test to obtain oauth_token and oauth_token_secret (Access tokens) from a Wordpress with WP-API and WP-OAuth plugins (and WP-CLI for OAuth consumer/app creation, for now) installed.

Author      : @kosso
Date        : Oct 29, 2014

// useful for further mods.. 
http://oauth.googlecode.com/svn/code/php/OAuth.php
which is used by .. 
https://developer.yahoo.com/boss/search/boss_api_guide/codeexamples.html#oauth_php

*/

session_start();


if($_GET['logout']==1){

    setcookie("access_token", "", 1 );
    setcookie("access_token_secret", "", 1 );
    setcookie("user_object", "", 1 );

    session_destroy();
    header('Location: '.$_SERVER['PHP_SELF']);

}


class OAuthWP
{

    function OAuthWP($config)
    {
        $this->key = $config['key'];
        $this->secret = $config['secret'];
        $this->uri_request = $config['uri_request'];
        $this->uri_authorize = $config['uri_authorize'];
        $this->uri_access = $config['uri_access'];     
        $this->uri_user = $config['uri_user'];           
    }


    function oauthRequest($url, $method, $oauth_access_token, $oauth_access_token_secret, $request_params = null){

        // Useful reading.. 
        // Signing Requests using HMAC-SHA1
        // https://developer.yahoo.com/oauth/guide/oauth-signing.html

        // Signing Requests using PLAINTEXT
        // https://developer.yahoo.com/oauth/guide/oauth-sign-plaintext.html

    
        $params = array(
            "oauth_version" => "1.0",
            "oauth_nonce" => time(),
            "oauth_timestamp" => time(),
            "oauth_consumer_key" => $this->key,
            "oauth_signature_method" => "HMAC-SHA1",
            "oauth_token" => $oauth_access_token
        );

        // ## BUILD OAUTH SIGNATURE


        if($request_params!=null){
            foreach ($request_params as $k => $v){
                    $params[$k] = $v;
            }
            uksort($params, 'strcmp');
        }


        
        // Encode params keys, values, join and then sort.
        $keys = $this->_urlencode_rfc3986(array_keys($params));
        $values = $this->_urlencode_rfc3986(array_values($params));
        $params = array_combine($keys, $values);
        uksort($params, 'strcmp');

        // Convert params to string 
        foreach ($params as $k => $v) {$pairs[] = $this->_urlencode_rfc3986($k).'='.$this->_urlencode_rfc3986($v);}
        $concatenatedParams = implode('&', $pairs);
        $concatenatedParams = str_replace('=', '%3D', $concatenatedParams);
        $concatenatedParams = str_replace('&', '%26', $concatenatedParams);

        // Form base string (first key)
        $baseString= $method."&".urlencode($url)."&".$concatenatedParams;


        // Form secret (second key)
        $secret = urlencode($this->secret)."&".$oauth_access_token_secret; // concatentate the oauth_token_secret 

        echo '<h3>client is using secret : '.$secret.'</h3>';

        


        // Make signature and append to params
        $params['oauth_signature'] = rawurlencode(base64_encode(hash_hmac('sha1', $baseString, $secret, TRUE)));
        
        // Re-sort params
        uksort($params, 'strcmp');


        // Build HTTP Authenticated Request Headers  (not used yet)
        $post_headers = $this->buildAuthorizationHeader($params);

        echo '<br>BASE STRING:<br><br>'.$baseString.'<br><br>PARAMS:<br><br>';
       // echo '<br>'.$post_headers.'<br>';

        print_r($params);

        // convert params to string 
        foreach ($params as $k => $v) {$urlPairs[] = $k."=".$v;}
        $concatenatedUrlParams = implode('&', $urlPairs);

        // form url
        $final_url = $url."?".$concatenatedUrlParams;

       // echo '<br><br>FINAL URL BEING CALLED BY CLIENT: <br>'.$final_url.'<br>';

        // Request using cURL
        $json_response = $this->_http($final_url, $request_params, $post_headers); 

        return $json_response;

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


        $request_method = 'POST'; // forced this here for now.

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

        // Request using cURL
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

        // Request using cURL
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
            curl_setopt($ch, CURLOPT_POST, 1);
            
            // had to use application/json, since other methods returned a missing callback paameter error.
            $header[] = 'Content-Type: application/json';
            curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
            
        }

        // Not being used yet. 
        if(isset($post_headers))
        {
            //echo '<hr>';
            //print_r($post_headers);
            //echo '<hr>';
            //curl_setopt($ch, CURLOPT_HTTPHEADER, $post_headers);
        }


        $response = curl_exec($ch);
        $this->http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->last_api_call = $url;
        curl_close($ch);

        echo '<hr>RESPONSE:<br>'.$response.'<hr>';

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
    'wp_api_domain'=>'http://yourdomain.com',
    'uri_request'=> 'http://yourdomain.com/oauth1/request',
    'uri_authorize'=> 'http://yourdomain.com/oauth1/authorize',
    'uri_access'=> 'http://yourdomain.com/oauth1/access',
    'uri_user'=> 'http://yourdomain.com/wp-json/users/me'
);



// Set the OAuth callback to return to this url, no matter where it's run from.
$callback_protocol = 'http';
if(isset($_SERVER['HTTPS'])){ $callback_protocol = 'https'; }
$oauth_config['oauth_callback'] = $callback_protocol.'://'.$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME'];

$auth = new OAuthWP($oauth_config);

echo '<pre>';

// Pick up url query params after the oauth_callback after request token generation. (Also added check to make sure we're coming back from the OAuth server host)
if(isset( $_REQUEST['oauth_token'] ) && isset( $_REQUEST['oauth_verifier'] ) && parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) == parse_url($oauth_config['uri_request'], PHP_URL_HOST)  ){
    
    // Generate access tokens param string
    $access_tokens = $auth->getAccessToken($_REQUEST['oauth_token'], $_REQUEST['oauth_verifier']);

    if(!isset($access_tokens['oauth_token'])){
        echo '<h3>ERROR: Failed to get access tokens</h3>';
        print_r($access_token);
        exit;
    }

    // Uncomment for more debug
    
    // echo '<h3>Success! Here are your Access Tokens :</h3>';
    // echo 'You should store these in the client somehow. Use a cookie or other storage method you need:<br><br>';
    // print_r($access_tokens);

    $access_token = $access_tokens['oauth_token'];
    $access_token_secret = $access_tokens['oauth_token_secret'];

    setcookie("access_token", $access_token, time() + (3600 * 72) );                 // expire in 72 hours...
    setcookie("access_token_secret", $access_token_secret, time() + (3600 * 72));    // expire in 72 hours...

    $user_object = json_decode($auth->oauthRequest($oauth_config['uri_user'],'GET', $access_token, $access_token_secret));

    setcookie("user_object", json_encode($user_object),  time() + (3600 * 72));    // expire in 72 hours...

    // Uncomment for more debug
    //echo '<h3>You appear to be logged in as : '.$user_object->username.'</h3>';
    //echo '<h5>User_object returned via WP-API</h5>';
    //print_r($user_object);


    // Send the now logged in user back to where we started...
    // header('Location : '.$_SERVER['PHP_SELF']);

    echo '<script> window.location = "'.$_SERVER['PHP_SELF'].'";</script>';


    exit;

}


if(isset($_COOKIE['access_token']) && isset($_COOKIE['access_token_secret']) && isset($_COOKIE['user_object'])){
    // Visitor already appears to have the cookies set. 
    echo '<h3>Logged in as: '.json_decode($_COOKIE['user_object'])->username.'</h3>';
    echo '<h3><a href="?logout=1">CLICK HERE TO LOG OUT</a></h3>';



    echo '<h3>OK.. Now try a post.... </h3>';   

   // $post_data[];

    $post_data = array(
        'status' => 'publish',
        'title' => 'Success! It actually worked!',
        'content_raw' => 'This is a post from a PHP client script running on another domain and server. It uses WP-API/WP-API and WP-API/Outh1.<h4>Pretty Sweet</h4>'
    );


    $post_object = json_decode($auth->oauthRequest($oauth_config['wp_api_domain'].'/wp-json/posts','POST', $_COOKIE['access_token'], $_COOKIE['access_token_secret'], $post_data));

    echo '<hr><h3>POST /wp-json/posts Response </h3>';

    print_r($post_object);


    
} else {
    // Not logged in. 
    // Start OAuth authorisation by obtaining a request token and generating a link to the OAuth server, with a callback here ...
    echo '<h3><a href="'.$oauth_config['uri_authorize'].'?'.$auth->getRequestToken().'&oauth_callback='.urlencode($oauth_config['oauth_callback']).'">LOGIN USING YOUR '.$oauth_config['wp_api_domain'].' WORDPRESS ACCOUNT</a></h3>';
    echo 'Uses WP-API and OAuth 1.0a Server for WordPress via https://github.com/WP-API. <br>(Also uses WP-CLI for app consumer setup : http://wp-cli.org/ until plugin has full admin UI)';


}

echo '</pre>';


?>