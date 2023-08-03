<?php

$wsdl = 'https://prueba.correoseguroandesscd.com.co/webService.php?wsdl'; //URL de nuestro servicio soap
$usuario = ""; //Credenciales Prueba Pagina Andes
$password = ""; //Credenciales Prueba Pagina Andes

$params = Array(
    "Arg1" => 5,
    "Arg2" => 10
    );

$options = Array(
	"uri"=> $wsdl,
	"style"=> SOAP_RPC,
	"use"=> SOAP_ENCODED,
	"soap_version"=> SOAP_1_1,
	"cache_wsdl"=> WSDL_CACHE_BOTH,
	"connection_timeout" => 15,
	"trace" => false,
	"encoding" => "UTF-8",
	"exceptions" => false,
	);

//Enviamos el Request
$soap = new SoapClient($wsdl, $options);
$soap->__setSoapHeaders(soapClientWSSecurityHeader($usuario, $password));

$arrayTest = array(
    "idUsuario" => '10',
    "Asunto" => 'Test mauro',
    "Texto" => 'TCorreo de prueba',
    "NombreDestinatario" => 'Andres Quintero',
    "CorreoDestinatario" => 'andres.quintero@andesscd.com.co',
    "Adjunto" => '',
    "NombreArchivo" => '',
    "Alertas" => '',
    "Recordatorio" => ''
    
);

$request = array('RegistrarMensajeRequest' => $arrayTest);
$result = $soap->__soapCall('RegistrarMensaje', $request);

print_r($result);


 function soapClientWSSecurityHeader($user, $password)
{
    $tm_created = gmdate('Y-m-d\TH:i:s\Z');
    $tm_expires = gmdate('Y-m-d\TH:i:s\Z', gmdate('U') + 180); //only necessary if using the timestamp element

    $simple_nonce = mt_rand();
    $encoded_nonce = base64_encode($simple_nonce);

    $passdigest = base64_encode(sha1($simple_nonce . $tm_created . $password, true));

    $ns_wsse = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    $ns_wsu = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    $password_type = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest';
    $encoding_type = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    $root = new SimpleXMLElement('<root/>');

    $security = $root->addChild('wsse:Security', null, $ns_wsse);
    $usernameToken = $security->addChild('wsse:UsernameToken', null, $ns_wsse);
    $usernameToken->addChild('wsse:Username', $user, $ns_wsse);
    $usernameToken->addChild('wsse:Password', $passdigest, $ns_wsse)->addAttribute('Type', $password_type);
    $usernameToken->addChild('wsse:Nonce', $encoded_nonce, $ns_wsse)->addAttribute('EncodingType', $encoding_type);
    $usernameToken->addChild('wsu:Created', $tm_created);

    $root->registerXPathNamespace('wsse', $ns_wsse);
    $full = $root->xpath('/root/wsse:Security');
    $auth = $full[0]->asXML();

    return new SoapHeader($ns_wsse, 'Security', new SoapVar($auth, XSD_ANYXML), true);
}


?>