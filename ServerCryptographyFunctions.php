<?php
$method = "aes-256-cbc";
$iv = "hdj27al8id5vmd45";
$connection_hash_key = "dsjhjhdhdusihdish";

$key = substr(hash("sha256", $connection_hash_key, true), 0, 32);
$functionEncryptData = function($data) use($method, $iv, $key){
    return base64_encode(openssl_encrypt($data, $method, $key, OPENSSL_RAW_DATA, $iv));
};
$functionDecryptData = function($data) use($method, $iv, $key){
    return openssl_decrypt(base64_decode($data), $method, $key, OPENSSL_RAW_DATA, $iv);
};
$functionPassword = function(){
    return strval(explode(" ", microtime())[1].explode(" ", microtime())[0]);
};
?>
