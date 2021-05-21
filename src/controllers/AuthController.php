<?php

namespace unionco\onelogin\controllers;

use Craft;
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
    protected $allowAnonymous = true;

    public function actionLogin()
    {
        /** @var Request */
        $request = Craft::$app->getRequest();

        /** @var ApiModule */
        $module = ApiModule::getInstance();

        /** @var LogService */
        $log = $module->log;

        /** @var Auth */
        $auth = OneLogin::$plugin->sp->getAuth();

        $auth->processResponse();

        if (!$auth->isAuthenticated()) {
            $lastErrorReason = $auth->getLastErrorReason() ?? 'Unknown';

            $log->log($auth->getSettings(), 'SAML Auth Config');
            $log->log($auth->getErrors(), 'SAML Auth - Errors', Logger::ERROR);
            $log->log($lastErrorReason, 'SAML Auth - Last Error Reason', Logger::ERROR);
            throw new UnauthorizedHttpException($lastErrorReason);
        }

        // Get the custom attributes, in this case we are only interested in the loginName
        // to find the Craft User
        $attributes = $auth->getAttributes();
        if (!$loginName = $attributes['loginName'][0] ?? false) {
            $log->log($attributes, 'loginName attribute not provided', Logger::ERROR);
            throw new BadRequestHttpException('LoginName is not provided');
        }

        $user = Craft::$app->getUsers()->getUserByUsernameOrEmail($loginName);
        if (!$user) {
            $log->log($loginName, 'Craft User lookup failed', Logger::ERROR);
            throw new ServerErrorHttpException('Could not find user with login: ' . $loginName);
        }

        // Get the session duration
        $generalConfig = Craft::$app->getConfig()->getGeneral();
        $duration = $generalConfig->userSessionDuration;

        if (!Craft::$app->getUser()->login($user, $duration)) {
            $log->log($loginName, 'Failed to login SSO user', Logger::ERROR);
            throw new UnauthorizedHttpException('Could not log in user');
        }

        $log->log(['loginName' => $loginName, 'craftUserId' => $user->id], 'Successfully logged in SSO user');
        return $this->redirect('/');
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
