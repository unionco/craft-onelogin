<?php

namespace unionco\onelogin\services;

use craft\base\Component;
use unionco\onelogin\OneLogin;
use OneLogin\api\OneLoginClient;
use yii\base\InvalidConfigException;

class AuthService extends Component
{
    /** @var null|OneLoginClient */
    private $_client = null;

    /**
     * @inheritdoc
     */
    public function init()
    {
        $this->getUsers();
    }

    /**
     * @return OneLoginClient
     */
    public function getClient()
    {
        if (!$this->_client) {
            $settings = OneLogin::$plugin->getSettings();
            if (!$settings->validate()) {
                throw new InvalidConfigException('OneLogin configuration is invalid');
            }
            $clientId = $settings->getClientId();
            $clientSecret = $settings->getClientSecret();
            $region = $settings->getRegion();
            $maxResults = $settings->getMaxResults();

            $this->_client = new OneLoginClient($clientId, $clientSecret, $region, $maxResults);
        }
    }

    public function getUsers()
    {
        $users = $this->getClient()->getUsers();
        print_r($users); die;
    }
}
