<?php

namespace unionco\onelogin\models;

use Craft;
use craft\base\Model;
use craft\helpers\App;
use unionco\onelogin\models\SAMLSettings;

class Settings extends Model
{
    /** @var string */
    public $clientId = '';

    /** @var string */
    public $clientSecret = '';

    /** @var string */
    public $region = 'us';

    /** @var string */
    public $maxResults = 1000;

    /** @var string */
    public $ssoPortalUrl = '';

    /** @var null|SAMLSettings */
    public $samlSettings = null;

    public function __construct()
    {
        $this->samlSettings = new SAMLSettings();
    }

    /**
     * @inheritdoc
     */
    public function rules(): array
    {
        return [
            // [['clientId', 'clientSecret', 'ssoPortalUrl',], 'required'],
        ];
    }

    /**
     * Get the value of clientId
     */
    public function getClientId(): string
    {
        return (string) App::parseEnv($this->clientId);
    }

    /**
     * Get the value of clientSecret
     */
    public function getClientSecret(): string
    {
        return (string) App::parseEnv($this->clientSecret);
    }

    /**
     * Get the value of region
     */
    public function getRegion(): string
    {
        return (string) App::parseEnv($this->region);
    }

    /**
     * Get the value of maxResults
     */
    public function getMaxResults(): int
    {
        return (int) App::parseEnv($this->maxResults);
    }

    public function getSsoPortalUrl(): string
    {
        return (string) App::parseEnv($this->ssoPortalUrl);
    }
}
