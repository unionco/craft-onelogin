<?php

namespace unionco\onelogin;

use Craft;
use craft\base\Model;
use yii\base\Event;
use craft\base\Plugin;
use craft\web\UrlManager;
use craft\i18n\PhpMessageSource;
use unionco\onelogin\models\Settings;
use craft\events\RegisterUrlRulesEvent;
use craft\helpers\UrlHelper;
use unionco\onelogin\models\SAMLSettings;
use unionco\onelogin\services\AuthService;
use unionco\onelogin\services\ServiceProviderService;

class OneLogin extends Plugin
{
    /** @var self */
    public static $plugin = null;

    /** @var string */
    public string $schemaVersion = '0.0.1';

    public bool $hasCpSettings = true;

    /**
     * @inheritdoc.
     */
    public function __construct($id, $parent = null, array $config = [])
    {
        Craft::setAlias('@unionco/onelogin', $this->getBasePath());

        $i18n = Craft::$app->getI18n();
        /** @noinspection UnSafeIsSetOverArrayInspection */
        if (!isset($i18n->translations[$id]) && !isset($i18n->translations[$id . '*'])) {
            $i18n->translations[$id] = [
                'class' => PhpMessageSource::class,
                'sourceLanguage' => 'en-US',
                'basePath' => 'onelogin/translations',
                'forceTranslation' => true,
                'allowOverrides' => true,
            ];
        }
        parent::__construct($id, $parent, $config);
    }

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();

        if (!static::$plugin) {
            static::$plugin = $this;
        }

        $this->controllerNamespace = 'unionco\\onelogin\\controllers';

        $this->_registerComponents();
        $this->_registerEventListeners();
        $this->_pluginLoaded();
    }

    /**
     * @inheritdoc
     */
    protected function createSettingsModel(): ?Model
    {
        return new Settings();
    }

    // /**
    //  * @inheritdoc
    //  */
    // protected function settingsHtml()
    // {
    //     return Craft::$app->getView()
    //         ->renderTemplate(
    //             'onelogin/settings',
    //             [
    //                 'settings' => $this->getSettings(),
    //             ]
    //         );
    // }
    public function getSettingsResponse(): mixed
    {
        return Craft::$app->getResponse()->redirect(UrlHelper::cpUrl('onelogin/settings/saml'));
    }

    /**
     * This method returns an array of settings for the onelogin\php-saml library
     */
    public function getSAMLSettings()
    {
        return new SAMLSettings();
        // return SAMLSettings::getSettings();
    }


    // Private Methods
    // ================

    /**
     * @return void
     */
    private function _registerComponents()
    {
        $this->setComponents([
            'onelogin' => AuthService::class,
            'sp' => ServiceProviderService::class,
        ]);
    }

    private function _registerEventListeners()
    {
        /**
         * CP routes
         */
        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_CP_URL_RULES,
            function (RegisterUrlRulesEvent $event): void
            {
                $event->rules = array_merge($event->rules, [
                    'login' => 'onelogin/cp/login',
                ]);
            }
        );
    }

    private function _pluginLoaded()
    {
        Craft::info(
            /** @psalm-suppress UndefinedClass */
            Craft::t(
                'onelogin',
                '{name} plugin loaded',
                ['name' => $this->name]
            ),
            __METHOD__
        );
    }
}
