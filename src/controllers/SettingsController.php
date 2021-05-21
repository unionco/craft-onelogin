<?php

namespace unionco\onelogin\controllers;

use Craft;
use yii\web\Response;
use craft\web\Controller;
use unionco\onelogin\models\SAMLSettings;
use unionco\onelogin\OneLogin;

class SettingsController extends Controller
{
    public function actionEdit(): Response
    {
        $settings = OneLogin::$plugin->getSettings();

        $variables = [
            'settings' => $settings,
        ];

        return $this->renderTemplate('onelogin/settings/saml', $variables);
    }

    public function actionSaveSettings()
    {
        $this->requirePostRequest();

        $params = Craft::$app->getRequest()->getBodyParams();
        $settings = OneLogin::$plugin->getSettings();
        $page = $params['page'] ?? null;
        switch ($page) {
            case 'saml':
                $samlSettings = new SAMLSettings($settings->samlSettings ?? []);
                $samlSettings->baseUrl = $params['baseUrl'] ?? '';
                $samlSettings->spEntityId = $params['spEntityId'] ?? '';
                $samlSettings->spAcsUrl = $params['spAcsUrl'] ?? '';
                $samlSettings->spSloUrl = $params['spSloUrl'] ?? '';
                $samlSettings->idpEntityId = $params['idpEntityId'] ?? '';
                $samlSettings->idpSsoUrl = $params['idpSsoUrl'] ?? '';
                $samlSettings->idpSloUrl = $params['idpSloUrl'] ?? '';
                $samlSettings->idpX509Cert = $params['idpX509Cert'] ?? '';
                $settings->samlSettings = $samlSettings;
                break;
            case 'portal':
                $settings->ssoPortalUrl = $params['ssoPortalUrl'] ?? '';
                break;
            case 'onelogin':
                $settings->clientId = $params['clientId'] ?? '';
                $settings->clientSecret = $params['clientSecret'] ?? '';
                $settings->region = $params['region'] ?? 'us';
                $settings->maxResults = $params['maxResults'] ?? 1000;
                break;
            default:
                Craft::$app->getSession()->setError('Unknown settings page.');
                return $this->renderTemplate('onelogin/settings/saml', compact('settings'));
                break;
        }

        $pluginSettingsSaved = Craft::$app->getPlugins()->savePluginSettings(OneLogin::$plugin, $settings->toArray());
        if (!$pluginSettingsSaved || !$settings->validate()) {
            Craft::$app->getSession()->setError("Couldn't save settings.");
            return $this->renderTemplate('onelogin/settings/saml', compact('settings'));
        }
        Craft::$app->getSession()->setNotice('Settings saved.');

        return $this->redirectToPostedUrl();
    }
}
