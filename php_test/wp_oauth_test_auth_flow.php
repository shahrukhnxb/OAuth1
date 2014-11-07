<?php

/*

wp_oauth_test_auth_flow.php

Description : Simple PHP test to obtain access_token and access_token_secret (Access tokens) from a Wordpress with WP-API and WP-OAuth plugins (and WP-CLI for OAuth consumer/app creation) installed.

Author      : @kosso
Date        : Nov 07, 2014

// See initial config and testing right down below.

*/

// We'll be setting some cookies for tests afte the login/connect flow. 
session_start();


// Clear the cookies to log out. 
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

    function oauthRequest($url, $method, $oauth_access_token, $oauth_access_token_secret, $post_params=null){
        
        // NB: All the echo and print_r must be commented out for setcookie to work when running logging in tests.

        $params = array(
            "oauth_version" => "1.0",
            "oauth_nonce" => md5(time().rand()),
            "oauth_timestamp" => time(),
            "oauth_consumer_key" => $this->key,
            "oauth_signature_method" => "HMAC-SHA1",
            "oauth_token" => $oauth_access_token
        );
        // filter out empty params. 
        $params = array_filter($params);

        // ## BUILD OAUTH SIGNATURE

        // Add extra params if present
        if($post_params!=null){
            foreach ($post_params as $k => $v){
                    $params[$k] = $v;
            }
            // Remove 'file' param from signature base string. Since the server will have nothing to compare it to. Also potentially exposes paths.
            unset($params['file']);
            ksort($params);
        }


        // deal query with any query params in the request_uri
        $request_query = parse_url($url, PHP_URL_QUERY);
        $request_uri_parts = parse_url($url);

        $request_base_uri = $request_uri_parts['scheme'].'://'.$request_uri_parts['host'].$request_uri_parts['path'];
        
        $joiner = '?'; // used for final url concatenation down below
        if(!empty($request_query)){
            $joiner = '&';
            parse_str($request_query, $query_params);
            $params = array_merge($query_params, $params);
            ksort($params);

        }

        // Encode params keys, values, join and then sort.
        $keys = $this->_urlencode_rfc3986(array_keys($params));
        $values = $this->_urlencode_rfc3986(array_values($params));
        $params = array_combine($keys, $values);
        ksort($params);

        // echo '<h4>ALL UNIQUE ENCODED PARAMS: (to create the base string)</h4>';
        // print_r($params);

        // Convert params to string 
        foreach ($params as $k => $v) {$pairs[] = $this->_urlencode_rfc3986($k).'='.$this->_urlencode_rfc3986($v);}
        $concatenatedParams = implode('&', $pairs);
        $concatenatedParams = str_replace('=', '%3D', $concatenatedParams);
        $concatenatedParams = str_replace('&', '%26', $concatenatedParams);

        // Form base string (first key)
        // echo '<h4>concat params : '.$concatenatedParams.'</h4>';

        // base string should never use the '?' even if it has one in a GET query
        // See : https://developers.google.com/accounts/docs/OAuth_ref#SigningOAuth

        $baseString= $method."&".urlencode($request_base_uri)."&".$concatenatedParams;

        // Form secret (second key)
        $secret = urlencode($this->secret)."&".$oauth_access_token_secret; // concatentate the oauth_token_secret (null when doing initial '1st leg' request token)

        // Make signature and append to params
        $params['oauth_signature'] = rawurlencode(base64_encode(hash_hmac('sha1', $baseString, $secret, TRUE)));
        
        // Re-sort params
        ksort($params);

        // RESULT SIGNATURE (to look at to compare to what's going on on when it reaches the server)
        // echo '<br>BASE STRING:<br>'.$baseString.'<br><br>SIGNED WITH : '.$secret.'<br><br>CREATED SIGNATURE:<br>'.$params['oauth_signature'].'<br>';

        // remove any added GET query parameters from the params to rebuild the string without duplication ..
        if(isset($query_params)){
            foreach ($query_params as $key => $value) {
                if(isset($params[$key])){
                    unset($params[$key]);
                }
            }
            ksort($params);
        }
        // remove any POST params so they get sent as POST data and not in the query string. 
        if(!empty($post_params)){
            foreach ($post_params as $key => $value) {
                if(isset($params[$key])){
                    unset($params[$key]);
                }
            }
            ksort($params);
        }

        // Build OAuth Authorization header from oauth_* parameters only.
        $post_headers = $this->buildAuthorizationHeader($params);

        // echo 'SEND '.$method.' request USING these OAuth Headers: ';
        // print_r($post_headers);

        // convert params to string 
        foreach ($params as $k => $v) {$urlPairs[] = $k."=".$v;}
        $concatenatedUrlParams = implode('&', $urlPairs);

        // the final url can use the ? query params....
        $final_url = $url; // original url. OAuth data will be set in the Authorization Header of the request, regardless of _GET or _POST (or _FILE)

        // Request using cURL
        $json_response = $this->_http($final_url, $method, $post_params, $post_headers); 

        return $json_response;

    }


    function getAccessToken($oauth_token, $oauth_verifier)
    {
        // Default params
        $params = array(
            "oauth_version" => "1.0",
            "oauth_nonce" => md5 ( uniqid ( rand(), true ) ),
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
        ksort($params);

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
        ksort($params);

        // Build HTTP Authenticated Request Headers  (not used yet)
        $post_headers = $this->buildAuthorizationHeader($params);

        // Convert params to string 
        foreach ($params as $k => $v) {$urlPairs[] = $k."=".$v;}
        $concatenatedUrlParams = implode('&', $urlPairs);

        // Form the final url
        $url = $this->uri_access."?".$concatenatedUrlParams;

        // Request using cURL
        $access_tokens = $this->_http($url, $request_method, $concatenatedUrlParams, $post_headers); 
        
        // Extract the values from the query paam
        parse_str($access_tokens, $output);

        return $output;

    }


    // SEND AUTHORISED REQUEST USING CURL ///////////////////////////
    function _http($url, $method, $post_data = null, $oauth_headers = null)
    {       
        $ch = curl_init();

        //echo '<hr>';
        //echo '_http: '.$method.' : url : '.$url;
        //echo '<hr>';

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);


        if($method=='POST')
        {
            curl_setopt($ch, CURLOPT_POST, 1);            

            //echo '<h4>POST : post_data</h4>';
            //print_r($post_data);

            if(isset($post_data['file'])){
                // Media upload
                $header[] = 'Content-Type: multipart/form-data';

                if(isset($oauth_headers)){
                    array_push($header, $oauth_headers);
                }

                //echo '<h4>setting POST (with _file) headers</h4>';
                //print_r($oauth_headers);    

                curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
            } else {

                $header[] = 'Content-Type: application/json';
                // commented out. going to try and send as multipart/form-data 

                if(isset($oauth_headers)){
                    //echo '<h4>POST : setting OAuth Authorization headers</h4>';
                    //print_r($oauth_headers);    
                    $header[] = $oauth_headers;
                    //echo '<h4>CURL final HTTP_HEADER </h4>';
                    //print_r($header);
                    curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
                }
 
                //echo '<h4>CURL final post_data </h4>';
                //print_r(json_encode($post_data));    

                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
            }

        } else {

            // Not being used yet. 
            if(isset($oauth_headers))
            {

                //echo '<h4>GET : setting OAuth Authorization headers</h4>';
                //print_r($oauth_headers);
                 
                $header[] = $oauth_headers;

                //echo '<h4>GET CURL final HTTP_HEADER </h4>';
                //print_r($header);
                                  
                curl_setopt($ch, CURLOPT_HTTPHEADER, $header);

            }

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
    'wp_api_domain'=>'http://your.wp.domain',
    'uri_request'=> 'http://your.wp.domain/oauth1/request',
    'uri_authorize'=> 'http://your.wp.domain/oauth1/authorize',
    'uri_access'=> 'http://your.wp.domain/oauth1/access',
    'uri_user'=> 'http://your.wp.domain/wp-json/users/me?context=embed' // 'embed' context excludes roles and capabilities
);


// Set the OAuth callback to return to this url, no matter where it's run from.
$callback_protocol = 'http';
if(isset($_SERVER['HTTPS'])){ $callback_protocol = 'https'; }
$oauth_config['oauth_callback'] = $callback_protocol.'://'.$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME'];

$auth = new OAuthWP($oauth_config);

// echo '<pre>';

// Pick up url query params after the oauth_callback after request token generation. (Also added check to make sure we're coming back from the OAuth server host)
if(isset( $_REQUEST['oauth_token'] ) && isset( $_REQUEST['oauth_verifier'] ) && parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) == parse_url($oauth_config['uri_request'], PHP_URL_HOST)  ){

    // Back from Authorisation. Now Generate Access Tokens for this user    
    // Generate access tokens param string

    // Add the required 'oauth_verifier' parameter
    $request_data = array(
        'oauth_verifier' => $_REQUEST['oauth_verifier']
    );
    $access_token_string = $auth->oauthRequest($oauth_config['uri_access'],'POST', $_REQUEST['oauth_token'], null, $request_data); // no token secret yet... 

    parse_str($access_token_string, $access_tokens);

    if(!isset($access_tokens['oauth_token'])){
        echo '<h3>ERROR: Failed to get access tokens</h3>';
        print_r($access_token);
        exit;
    }

    $access_token = $access_tokens['oauth_token'];
    $access_token_secret = $access_tokens['oauth_token_secret'];

    // Verify user by getting currently looged in user daya from /wp-json/users/me 
    $user_object = json_decode($auth->oauthRequest($oauth_config['uri_user'],'GET', $access_token, $access_token_secret));

    // Store information in a cookie for when the page is reloaded
    setcookie("access_token", $access_token, time() + (3600 * 72) );                 // expire in 72 hours...
    setcookie("access_token_secret", $access_token_secret, time() + (3600 * 72));    // expire in 72 hours...
    setcookie("user_object", json_encode($user_object),  time() + (3600 * 72));    // expire in 72 hours...

    // Send the now logged in user back to where we started...
    echo '<script> window.location = "'.$_SERVER['PHP_SELF'].'";</script>';

    exit;

}

if(isset($_COOKIE['access_token']) && isset($_COOKIE['access_token_secret']) && isset($_COOKIE['user_object'])){
    // Visitor already appears to have the required cookies set. 
    echo '<h3>Logged in as: '.json_decode($_COOKIE['user_object'])->username.'</h3>';

    echo '<h4><a href="?logout=1">CLICK HERE TO LOG OUT</a></h4>';
    echo '<hr>';

    // TESTS /////////////////////////////////////////////

    /*
    // TEST : GET CURRENT USER DATA 
    // Docs : http://wp-api.org/#users_retrieve-current-user

    echo '<h3>TEST: GET : /wp-json/users/me  to verify current user</h3>';
    $current_user_object = json_decode($auth->oauthRequest($oauth_config['uri_user'],'GET', $_COOKIE['access_token'], $_COOKIE['access_token_secret'])); 
    echo '<h4>RESPONSE:</h4>';
    echo '<pre>';
    print_r($current_user_object);   
    echo '</pre>';
    */


    /* 
    // TEST : CREATE NEW ATTACHMENT (Media upload)
    // Docs : http://wp-api.org/#media_create-an-attachment
   
    echo '<pre>';
    echo '<h3>TEST : CREATE NEW ATTACHMENT (Media upload)</h3>';   
    $file_data = array(
        'file' => '@/path/to/a/file.jpg;type=image/jpeg'
    );
    $file_object = json_decode($auth->oauthRequest($oauth_config['wp_api_domain'].'/wp-json/media','POST', $_COOKIE['access_token'], $_COOKIE['access_token_secret'], $file_data));
    echo '</pre>';

    echo '<h4>RESPONSE:</h4>';
    echo '<pre>';    
    print_r($file_object);
    echo '</pre>';  
    */
    
    // Naturally, you'd need to do a file upload first, if you want the attachment to be 'attached' or embedded in a post.

    /*
    // TEST : CREATE A NEW POST
    // Docs : http://wp-api.org/#posts_create-a-post
    echo '<hr><h3>Test : Create new post</h3>';   
    $post_data = array(
        //'status' => 'publish',
        'title' => 'Another test at '.date('H:i'),
        'content_raw' => 'The quick brown fox jumped over the lazy dogs.'
    );

    $post_object = json_decode($auth->oauthRequest($oauth_config['wp_api_domain'].'/wp-json/posts','POST', $_COOKIE['access_token'], $_COOKIE['access_token_secret'], $post_data));

    echo '<h4>RESPONSE:</h4>';
    echo '<pre>';    
    print_r($post_object);
    echo '</pre>';    
    */

    
    /*
    // For JavaScript testing ... 
    echo '<script>

        var access_token = readCookie("access_token");
        var access_token_secret = readCookie("access_token_secret");

        console.log(access_token);
        console.log(access_token_secret);

         function createCookie(name, value, days) {
            if (days) {
                var date = new Date();
                date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
                var expires = "; expires=" + date.toGMTString();
            } else var expires = "";
            document.cookie = escape(name) + "=" + escape(value) + expires + "; path=/";
        }

        function readCookie(name) {
            var nameEQ = escape(name) + "=";
            var ca = document.cookie.split(";");
            for (var i = 0; i < ca.length; i++) {
                var c = ca[i];
                while (c.charAt(0) == " ") c = c.substring(1, c.length);
                if (c.indexOf(nameEQ) == 0) return unescape(c.substring(nameEQ.length, c.length));
            }
            return null;
        }

        function eraseCookie(name) {
            createCookie(name, "", -1);
        }

    </script>';
    */

    // that's it..

    
} else {
    // Not logged in. 

    $request_token_string = $auth->oauthRequest($oauth_config['uri_request'],'POST', null, null);


    // echo '<h4>'.$request_token_string.'</h4>';
    // Start OAuth authorisation by obtaining a request token and generating a link to the OAuth server, with a callback here ...
    echo '<h3><a href="'.$oauth_config['uri_authorize'].'?'.$request_token_string.'&oauth_callback='.urlencode($oauth_config['oauth_callback']).'">LOGIN USING YOUR '.$oauth_config['wp_api_domain'].' WORDPRESS ACCOUNT</a></h3>';
    echo 'Uses WP-API and OAuth 1.0a Server for WordPress via https://github.com/WP-API. <br>(Also uses WP-CLI for app consumer setup : http://wp-cli.org/ until plugin has full admin UI)';


}


?>