<?php

namespace unionco\onelogin\services;

use OneLogin\Saml2\Auth;
use craft\base\Component;
use unionco\onelogin\models\SAMLSettings;
use unionco\onelogin\OneLogin;

class ServiceProviderService extends Component
{
    /** @var Auth|null */
    private $auth;

    public function init()
    {
        $settings = OneLogin::$plugin->getSettings()->samlSettings ?? [];
        $samlSettings = new SAMLSettings($settings);

        $this->auth = new Auth($samlSettings->getSettingsArray());
    }

    public function getAuth(): Auth
    {
        return $this->auth;
    }
}
