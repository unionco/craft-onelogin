<?php

namespace unionco\onelogin\controllers;

use yii\web\Response;
use craft\web\Controller;
use unionco\onelogin\OneLogin;

class CpController extends Controller
{
    public $allowAnonymous = ['login'];

    public function actionLogin(): Response
    {
        $settings = OneLogin::$plugin->getSettings();
        $provider = [
            'label' => 'OneLogin',
            'url' => $settings->getSsoPortalUrl(),
        ];
        return $this->renderTemplate('onelogin/login', compact('provider'));
    }
}
