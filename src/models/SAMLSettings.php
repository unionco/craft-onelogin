<?php

namespace unionco\onelogin\models;

use craft\base\Model;
use Craft;
use yii\base\InvalidConfigException;

class SAMLSettings extends Model
{
    /** @var bool Debug Mode */
    public $debug = false;

    /** @var string Local Onelogin base URL */
    public $baseUrl;

    /** @var array */
    public $spAttributes = [];

    /** @var null|string Service Provider | Entity ID */
    public $spEntityId;

    /** @var null|string Service Provider | Assertion Consumer Service | URL*/
    public $spAcsUrl;

    /** @var string Service Provider | Single-logout | URL */
    public $spSloUrl;

    /** @var string Identity Provider | Entity ID*/
    public $idpEntityId;

    /** @var string Identity Provider | SSO URL */
    public $idpSsoUrl;

    /** @var string Identity Provider | Single-Logout | URL */
    public $idpSloUrl;

    /** @var string Identity Provider | X.509 Certificate filepath or cert contents*/
    public $idpX509Cert;

    public function rules()
    {
        return [
            [[
                'baseUrl',
                'spEntityId', 'spAcsUrl', 'spSloUrl',
                'idpEntityId', 'idpSsoUrl', 'idpSloUrl', 'idpX509Cert',
            ], 'required'],
            ['spEntityId', 'string'],
            ['baseUrl', 'string'],
            ['spAcsUrl', 'string'],
            ['idpX509Cert', 'string'],
        ];
    }

    public function getDebug()
    {
        return $this->debug;
    }

    public function getBaseUrl()
    {
        return Craft::parseEnv($this->baseUrl);
    }

    public function getSpAttributes()
    {
        return [
            [
                'name' => 'loginName',
                'isRequired' => true,
                'nameFormat' => 'string',
                'friendlyName' => 'loginName',
                'attributeValue' => '',
            ],
        ];
    }

    public function getSpEntityId()
    {
        return Craft::parseEnv($this->spEntityId);
    }

    public function getSpAcsUrl()
    {
        return Craft::parseEnv($this->spAcsUrl);
    }

    // public function getIdpSsoUrl()
    // {
    //     return Craft::parseEnv($this->idpSsoUrl);
    // }

    public function getSpSloUrl()
    {
        return Craft::parseEnv($this->spSloUrl);
    }

    public function getIdpEntityId()
    {
        return Craft::parseEnv($this->idpEntityId);
    }

    public function getIdpSsoUrl()
    {
        return Craft::parseEnv($this->idpSsoUrl);
    }

    public function getIdpSloUrl()
    {
        return Craft::parseEnv($this->idpSloUrl);
    }

    public function getIdpX509Cert()
    {
        $certFilePath = Craft::parseEnv($this->idpX509Cert);

        $cert = null;
        if ($this->idpX509Cert && file_exists($certFilePath)) {
            $cert = file_get_contents($certFilePath);
        } elseif (strpos($certFilePath, '-----BEGIN CERTIFICATE-----')) {
            // Cert contents are already set
            $cert = $certFilePath;
        }
        return $cert;
    }
    // public function __construct()
    // {
    //     $this->debug = getenv('ONELOGIN_DEBUG');
    //     if ($this->debug === true || $this->debug === 'true') {
    //         $this->debug = true;
    //     } else {
    //         $this->debug = false;
    //     }

    //     $this->baseUrl = getenv('BASE_URL') . '/actions/onelogin';
    //     $this->spAttributes = [
    //         [
    //             'name' => 'loginName',
    //             'isRequired' => true,
    //             'nameFormat' => 'string',
    //             'friendlyName' => 'loginName',
    //             'attributeValue' => '',
    //         ],
    //     ];
    //     $this->spEntityId = getenv('ONELOGIN_SP_ENTITY_ID');
    //     if (!$this->spEntityId) {
    //         $this->spEntityId = '/auth/login';
    //     }

    //     $this->spAcsUrl = getenv('ONELOGIN_SP_ACS_URL');
    //     if (!$this->spAcsUrl) {
    //         $defaultSpAcsUrl = $this->baseUrl . '/auth/login';
    //         $this->spAcsUrl = $defaultSpAcsUrl;
    //     }

    //     $this->idpEntityId = getenv('ONELOGIN_IDP_ENTITY_ID');
    //     $this->idpSsoUrl = getenv('ONELOGIN_IDP_SSO_URL');
    //     $this->idpX509Cert = getenv('ONELOGIN_X509_CERT');

    //     $certFilePath = CRAFT_BASE_PATH . '/' . $this->idpX509Cert;
    //     if ($this->idpX509Cert && file_exists($certFilePath)) {
    //         $this->idpX509Cert = file_get_contents($certFilePath);
    //     } elseif (strpos($this->idpX509Cert, '-----BEGIN CERTIFICATE-----')) {
    //         // Cert contents are already set
    //     } else {
    //         throw new InvalidConfigException('Could not find X.509 Certificate');
    //     }
    // }

    public function getSettingsArray(): array
    {
        return [
            // If 'strict' is True, then the PHP Toolkit will reject unsigned
            // or unencrypted messages if it expects them signed or encrypted
            // Also will reject the messages if not strictly follow the SAML
            // standard: Destination, NameId, Conditions ... are validated too.
            'strict' => false,

            // Enable debug mode (to print errors)
            'debug' => $this->getDebug(),

            // Set a BaseURL to be used instead of try to guess
            // the BaseURL of the view that process the SAML Message.
            // Ex. http://sp.example.com/
            //     http://example.com/sp/
            'baseurl' => $this->getBaseUrl(),

            // Service Provider Data that we are deploying
            'sp' => [
                // Identifier of the SP entity  (must be a URI)
                'entityId' => $this->getSpEntityId(),
                // Specifies info about where and how the <AuthnResponse> message MUST be
                // returned to the requester, in this case our SP.
                'assertionConsumerService' => [
                    // URL Location where the <Response> from the IdP will be returned
                    'url' => $this->getSpAcsUrl(),
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-POST binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ],
                // If you need to specify requested attributes, set a
                // attributeConsumingService. nameFormat, attributeValue and
                // friendlyName can be omitted. Otherwise remove this section.
                "attributeConsumingService" => [
                    "serviceName" => "SP test",
                    "serviceDescription" => "Test Service",
                    "requestedAttributes" => $this->getSpAttributes(),
                ],
                // Specifies info about where and how the <Logout Response> message MUST be
                // returned to the requester, in this case our SP.
                'singleLogoutService' => [
                    // URL Location where the <Response> from the IdP will be returned
                    'url' => $this->getSpSloUrl(),
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],
                // Specifies constraints on the name identifier to be used to
                // represent the requested subject.
                // Take a look on lib/Saml2/Constants.php to see the NameIdFormat supported
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',

                // Usually x509cert and privateKey of the SP are provided by files placed at
                // the certs folder. But we can also provide them with the following parameters
                'x509cert' => '',
                'privateKey' => '',

                /*
                * Key rollover
                * If you plan to update the SP x509cert and privateKey
                * you can define here the new x509cert and it will be
                * published on the SP metadata so Identity Providers can
                * read them and get ready for rollover.
                */
                // 'x509certNew' => '',
            ],

            // Identity Provider Data that we want connect with our SP
            'idp' => [
                // Identifier of the IdP entity  (must be a URI)
                'entityId' => $this->getIdpEntityId(),
                // SSO endpoint info of the IdP. (Authentication Request protocol)
                'singleSignOnService' => [
                    // URL Target of the IdP where the SP will send the Authentication Request Message
                    'url' => $this->getIdpSsoUrl(),
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],
                // SLO endpoint info of the IdP.
                'singleLogoutService' => [
                    // URL Location of the IdP where the SP will send the SLO Request
                    'url' => $this->getIdpSloUrl(),
                    // URL location of the IdP where the SP SLO Response will be sent (ResponseLocation)
                    // if not set, url for the SLO Request will be used
                    'responseUrl' => '',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],
                // Public x509 certificate of the IdP
                'x509cert' => $this->getIdpX509Cert(),
                /**
             *  Instead of use the whole x509cert you can use a fingerprint in
             *  order to validate the SAMLResponse, but we don't recommend to use
             *  that method on production since is exploitable by a collision
             *  attack
             *  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it,
             *   or add for example the -sha256 , -sha384 or -sha512 parameter)
             *
             *  If a fingerprint is provided, then the certFingerprintAlgorithm is required in order to
             *  let the toolkit know which Algorithm was used. Possible values: sha1, sha256, sha384 or sha512
             *  'sha1' is the default value.
             */
                // 'certFingerprint' => 'DF 2A 2F 08 00 B7 B7 1F 7C F1 E2 E4 79 7C DD 79 22 F2 27 F7',
                // 'certFingerprintAlgorithm' => 'sha1',

                /* In some scenarios the IdP uses different certificates for
                * signing/encryption, or is under key rollover phase and more
                * than one certificate is published on IdP metadata.
                * In order to handle that the toolkit offers that parameter
                * (when used, 'x509cert' and 'certFingerprint' values are
                * ignored).
                */
                // 'x509certMulti' => array(
                //      'signing' => array(
                //          0 => '<cert1-string>',
                //      ),
                //      'encryption' => array(
                //          0 => '<cert2-string>',
                //      )
                // ),
            ],
        ];
    }
}
