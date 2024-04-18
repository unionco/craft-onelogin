<?php

namespace unionco\onelogin\controllers;

use Craft;
use craft\elements\User;
use Monolog\Logger;
use SAML2\Response;
use craft\web\Request;
use OneLogin\Saml2\Auth;
use union\api\ApiModule;
use craft\web\Controller;
use unionco\onelogin\OneLogin;
use union\api\services\LogService;
use yii\web\BadRequestHttpException;
use yii\web\ServerErrorHttpException;
use yii\web\UnauthorizedHttpException;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class AuthController extends Controller
{
    protected array|bool|int $allowAnonymous = self::ALLOW_ANONYMOUS_LIVE;

    public function actionSsoRedirect()
    {
        $request = Craft::$app->getRequest();
        $context = $request->getQueryParam('context');
        $auth = OneLogin::$plugin->sp->getAuth();
        $response = $auth->login($context);

        return $response;
    }

    public function actionLogin()
    {
        /** @var Request */
        $request = Craft::$app->getRequest();

        // /** @var ApiModule */
        // $module = ApiModule::getInstance();

        // /** @var LogService */
        // $log = $module->log;

        /** @var Auth */
        $auth = OneLogin::$plugin->sp->getAuth();

        $auth->processResponse();

        if (!$auth->isAuthenticated()) {
            $lastErrorReason = $auth->getLastErrorReason() ?? 'Unknown';
            LogService::log($auth->getSettings(), 'one-login.log');
            LogService::log($auth->getErrors(), 'one-login.log');
            LogService::log($lastErrorReason, 'one-login.log');

            // $log->log($auth->getSettings(), 'SAML Auth Config');
            // $log->log($auth->getErrors(), 'SAML Auth - Errors', Logger::ERROR);
            // $log->log($lastErrorReason, 'SAML Auth - Last Error Reason', Logger::ERROR);
            throw new UnauthorizedHttpException($lastErrorReason);
        }

        // Get the custom attributes, in this case we are only interested in the loginName
        // to find the Craft User
        $loginName = $auth->getAttribute('loginName')[0] ?? $auth->getAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')[0] ?? null;
        if (!$loginName) {
            // $log->log($attributes, 'loginName attribute not provided', Logger::ERROR);
            throw new BadRequestHttpException('LoginName is not provided');
        }

        $user = Craft::$app->getUsers()->getUserByUsernameOrEmail($loginName);
        if (!$user) {
            // $log->log($loginName, 'Craft User lookup failed', Logger::ERROR);
            throw new ServerErrorHttpException('Could not find user with login: ' . $loginName);
        }

        // Get the session duration
        $generalConfig = Craft::$app->getConfig()->getGeneral();
        $duration = $generalConfig->userSessionDuration;

        $userService = Craft::$app->getUser();
        if (!$userService->login($user, $duration)) {
            // $log->log($loginName, 'Failed to login SSO user', Logger::ERROR);
            throw new UnauthorizedHttpException('Could not log in user');
        }

        $relayState = $request->getParam('RelayState');
        if ($relayState == 'cms') {
            return $this->redirect('https://' . $request->getHostName() . '/admin');
        } else {
            $token = ApiModule::$instance->getJWT()->buildToken($user);

            $authJson = json_encode([
                'success' => true,
                'token' => (string) $token,
                'user' => $user->transform()
            ]);
            $ssoEncoded = base64_encode($authJson);

            if (env('SSO_DEBUG')) {
                LogService::log('[SSO Login Success]: ' . env('SSO_RETURN_URL',  '/'), 'one-login.log');
                LogService::log($authJson, 'one-login.log');
            }

            Craft::$app->response->getHeaders()->add('acbj-sso', $ssoEncoded);

            return $this->redirect(env('SSO_RETURN_URL',  '/') . '?sso=' . $ssoEncoded);
        }

    }

    // https://dev.swiftpitch-cms.bizjournals.com/actions/onelogin/auth/login
    public function actionLoginTest()
    {
        if (env('ENVIRONMENT') !== 'dev') {
            return;
        }

        $_POST['SAMLResponse'] = file_get_contents(storage_path('onelogin/sample-response.http'));
        $ssoSettings = [
            'SSO_RETURN_URL' => env('SSO_RETURN_URL_DEBUG'),
            'SSO_SAML_SP_ENTITY_ID' => env('SSO_SAML_SP_ENTITY_ID_DEBUG'),
            'SSO_SAML_SP_CONSUMER_URL' => env('SSO_SAML_SP_CONSUMER_URL_DEBUG'),
            'SSO_SAML_SP_LOGOUT_URL' => env('SSO_SAML_SP_LOGOUT_URL_DEBUG'),
            'SSO_SAML_IDP_ENTITY_ID' => env('SSO_SAML_IDP_ENTITY_ID_DEBUG'),
            'SSO_SAML_IDP_SSO_URL' => env('SSO_SAML_IDP_SSO_URL_DEBUG'),
            'SSO_SAML_IDP_LOGOUT_URL' => env('SSO_SAML_IDP_LOGOUT_URL_DEBUG'),
            'SSO_SAML_IDP_X509=' => env('SSO_SAML_IDP_X509_DEBUG'),
            'SSO_PORTAL_URL' => env('SSO_PORTAL_URL_DEBUG'),
        ];
        foreach($ssoSettings as $ssoSetting => $ssoValue) {
            putenv($ssoSetting . '=' . $ssoValue);
            $_SERVER[$ssoSetting] = $ssoValue;
            $_ENV[$ssoSetting] = $ssoValue;
        }


        return $this->actionLogin();
    }

    private function handleSuccessfulLogin(bool $setNotice): \yii\web\Response
    {
        // Get the return URL
        $userSession = Craft::$app->getUser();
        $returnUrl = $userSession->getReturnUrl();

        // Clear it out
        $userSession->removeReturnUrl();

        // If this was an Ajax request, just return success:true
        $request = Craft::$app->getRequest();
        if ($request->getAcceptsJson()) {
            $return = [
                'success' => true,
                'returnUrl' => $returnUrl
            ];

            if (Craft::$app->getConfig()->getGeneral()->enableCsrfProtection) {
                $return['csrfTokenValue'] = $request->getCsrfToken();
            }

            return $this->asJson($return);
        }

        if ($setNotice) {
            Craft::$app->getSession()->setNotice(Craft::t('app', 'Logged in.'));
        }

        return $this->redirectToPostedUrl($userSession->getIdentity(), $returnUrl);
    }
}
