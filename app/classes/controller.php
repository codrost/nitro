<?php

namespace base;

use \Base as Base;
use \DB;
use Models;
use Views;
use \Classes\PasswordStorage as PasswordStorage;
use \Classes\Toolbox as Toolbox;
use Controllers;
use \Exception;
use \Sentry;

class Controller
{

    protected $f3;

    protected $db;

    protected $loginFailedLimit = 20;

    protected $routeLogging = [
        '/dashboard',
        '/workflow/requestlayer',
        '/forgotpassword',
        '/passwordreset-success',
        '/passwordreset',
        '/user/',
        '/user',
        '/azure/login',
        '/user/settings',
        '/search',
        '/pimbox/share',
        '/project',
        '/project/',
        '/company',
        '/company/',
        '/note',
        '/message',
        '/provider',
        '/provider/',
        '/environmentaccess',
        '/environment',
        '/livesharing/save',
        '/livesharing/stop'
    ];

    public function __construct()
    {
        $f3 = Base::instance();

        $connectionString = $f3->get('database.engine') . ':host=' . $f3->get('database.host') . ';port=' . $f3->get('database.port') . ';dbname=' . $f3->get('database.name');

        try {
            $db = new DB\SQL($connectionString, $f3->get('database.username'), $f3->get('database.password'));
        } catch (Exception $e) {
            \Sentry\captureException($e);
            \Sentry\captureMessage('Check your database or database settings in xxx.ini file');
            $f3->reroute('/error/Database niet gevonden<br>Neem contact op met PIMinfo');
        }

        $this->f3 = $f3;
        $this->db = $db;

        $this->db->log(false);

        $this->minify('js', [
            'public-functions.js',
            'public-main.js',
            'functions.js',
            'public-reaction.js',
            'main.js'
        ]);

        // Set default specified roles
        $sql = "SELECT id,position,tag,name,scope FROM user_profile WHERE `default`=1";
        $results = $this->db->exec($sql);
        foreach ($results as $result) {
            $authProfiles[$result['scope']][] = $result;
        }

        $f3->set('authorisationProfiles', $authProfiles);

        $f3->set('modernBrowser', function () {
            return $this->modernBrowser();
        });
        $f3->set('publicReaction', function () {
            return $this->f3->get('SESSION.public_reaction');
        });
        $f3->set('checkLogin', function () {
            return $this->checkLogin();
        });
        $f3->set('checkCollaboration', function () {
            return $this->checkCollaboration();
        });

        //contract checks
        $f3->set('checkVirtualProjectRoomAuthorization', function () {
            return $this->checkVirtualProjectRoomAuthorization();
        });
        $f3->set('checkRelaticsConnectionAuthorization', function () {
            return $this->checkRelaticsConnectionAuthorization();
        });
        $f3->set('checkPublicViewerAuthorization', function () {
            return $this->checkPublicViewerAuthorization();
        });
        $f3->set('checkPublicReactionAuthorization', function () {
            return $this->checkPublicReactionAuthorization();
        });
        $f3->set('checkRoLoketAuthorization', function () {
            return $this->checkRoLoketAuthorization();
        });

        $f3->set('hasPermission', function ($permission) {
            return $this->hasPermission($permission);
        });
    }

    /**
     * Called before route starts
     *
     * @return void
     */
    public function beforeRoute()
    {
        $this->f3->set('output', []);

        // if($this->f3->VERB == 'POST' || $this->f3->VERB=='PUT'){
        //     $tokenTimeout = 1800;
        //     $token = $this->f3->get('POST.token');
        //     $csrf = $this->f3->get('SESSION.CSRF');
        //     $csrfTime = $this->f3->get('SESSION.CSRFtime');

        //     if($token !== $csrf && (time() - $csrfTime) > $tokenTimeout){
        //         $this->f3->clear('SESSION.CSRF');
        //         $this->f3->clear('SESSION.CSRFtime');
        //         throw new Exception('CSRF attack!');
        //     }
        // }

        if ($this->f3->get('SERVER.REQUEST_METHOD') == 'PUT') {
            parse_str($this->f3->get('BODY'), $data);

            // Filter id field from post and put data
            // if(array_key_exists('id',$data)){
            //     unset($data['id']);
            // }

            array_walk($data, function (&$value, $key) {
                if (strpos($key, 'date') !== false) {
                    $date = new \DateTime($value);
                    $value = $date->format('Y-m-d 00:00:00');
                }
            });

            $this->f3->set('POST', $data);
        }

        if (strpos($this->f3->get('QUERY'), 'relatics|') !== false) {
            // http://localhost?relatics|70692924-9d69-424b-aaee-c51651f38dce||niet bestaand object|nb|niet bestaand object
            $relatics = explode('|', urldecode($this->f3->get('QUERY')));

            $workspaceId = $relatics[1];
            $uuid = $relatics[3];
            $layerName = $relatics[6];
        } else if (strtolower($this->f3->get('GET.view')) == 'embedded' || $this->f3->exists('GET.external_environmentid')) {
            // http://localhost?
            // & view=embedded                                                  required
            // & external_environmentid=70692924-9d69-424b-aaee-c51651f38dce    required
            // & objectid=trew-453-rtew-5345                                    required
            // & objectname=gebiedje x                                          optional
            // & layerid=stakeholders                                           optional
            // & search=breda                                                   optional

            $workspaceId = $this->f3->get('GET.external_environmentid');
            $uuid = $this->f3->get('GET.objectid');
            if ($this->f3->exists('GET.layerid')) {
                $layerid = $this->f3->get('QUERY.layerid');
            }
        }

        if (isset($workspaceId) && !empty($workspaceId)) {

            $queryParameters = [
                'environment_id' => '',
                'layers' => '',
                'uuid' => $uuid
            ];

            $environment = new Models\Environment($this->db);
            $environment->getByExternalProjectId($workspaceId);

            if (!$environment->dry()) {

                $queryParameters['environment_id'] = $environment->id;

                $sql = "SELECT 
                            l.id as layerId
                        FROM 
                            vector_dynamic as v 
                        LEFT JOIN
                            layer as l ON l.id=v.layer_id
                        WHERE 
                            v.uuid=? 
                            AND 
                                l.environment_id=? 
                            AND 
                                l.deleted_at IS NULL";

                $results = $this->db->exec($sql, [$uuid, $environment->id]);
                if (count($results)) {
                    $queryParameters['layers'] = (int) $results[0]['layerId'];
                } else {
                    $sql = "SELECT 
                            l.id as layerId
                        FROM 
                            vector_dynamic as v 
                        LEFT JOIN
                            layer as l ON l.id=v.layer_id
                        WHERE 
                                l.environment_id=? 
                            AND 
                                l.deleted_at IS NULL";

                    $results = $this->db->exec($sql, [$environment->id]);
                    if (count($results)) {
                        $queryParameters['layers'] = (int) $results[0]['layerId'];
                    } else {
                        $queryParameters['error'] = 'Geen interactieve kaartlaag in omgeving gevonden';
                    }
                }

                $this->f3->set('SESSION.last_query_parameters', $queryParameters);
                $this->f3->set('SESSION.environment_id', $queryParameters['environment_id']);
            } else {
                $queryParameters['error'] = 'Omgeving niet gevonden';
                $this->f3->set('SESSION.last_query_parameters', $queryParameters);
            }
        }

        if (strpos($this->f3->get('QUERY'), 'viewer=') !== false) {
            parse_str($this->f3->get('QUERY'), $queryParameters);
            $environment = new Models\Environment($this->db);
            $environment->load(['name=? AND public_access=1 AND deleted_at is null', $queryParameters['viewer']]);
            if (!$environment->dry()) {
                $this->f3->reroute('?environment_id=' . $environment->id);
            }
        }

        // backwards compatibility with project_environment_id
        if (strpos($this->f3->get('QUERY'), 'project_environment_id=') !== false) {
            $query = $this->f3->get('QUERY');
            $this->f3->set('QUERY', str_ireplace('project_environment_id', 'environment_id', $query));
        }

        if (strpos($this->f3->get('QUERY'), 'environment_id=') !== false) {
            parse_str($this->f3->get('QUERY'), $queryParameters);
            $this->f3->set('SESSION.last_query_parameters', $queryParameters);
            $this->f3->set('SESSION.environment_id', (int) $queryParameters['environment_id']);
            //reaction?
            $environment = new Models\Environment($this->db);
            $environment->load(['public_reaction=1 AND id=? AND deleted_at is null', $queryParameters['environment_id']]);
            if (!$environment->dry()) {
                $this->f3->set('SESSION.public_reaction', $environment->public_reaction);
            }
        }

        if ($this->f3->exists('SESSION.user') && $this->f3->get('SESSION.guest') === false) {
            Sentry\configureScope(function (Sentry\State\Scope $scope): void {
                $scope->setUser($this->f3->get('SESSION.user'));
            });
        }
    }

    /**
     * Called after route ended
     *
     * @return void
     */
    public function afterRoute()
    {

        if ($this->f3->exists('output.mimetype')) {

            header('Content-Type: ' . $this->f3->get('output.mimetype'));
            if (in_array($this->f3->get('output.mimetype'), ['image/png', 'image/jpg', 'image/jpeg'])) {
                /** 604800 = 1 week */
                header('Cache-Control: max-age=604800');
                header_remove('Pragma');
                header_remove('Expires');
            }

            echo $this->f3->get('output.content');
        } else if (!$this->f3->get('AJAX')) {
            //access?
            if (!$this->checkLogin() && $this->checkPublicAccess($this->f3->get("SESSION.environment_id"))) {
                //public
                echo \Template::instance()->render('layout.htm');
            } else if (!$this->checkLogin()) {
                //login first
                echo \Template::instance()->render('index.htm');
            } else {
                //already logged in so check environment
                $authorisation = new Controllers\Authorisation($this->db);
                $environmentId = $this->f3->get("SESSION.environment_id");
                if (!empty($environmentId) && $authorisation->checkEnvironmentAccess($environmentId)) {
                    //make sure the authorisations are set
                    $this->f3->set('SESSION.user.role', $authorisation->environmentRole($environmentId, $this->f3->get('SESSION.user.id')));
                    $this->f3->set('SESSION.user.authorisation', $authorisation->environmentAuthorisation());
                    $this->f3->clear('SESSION.collaboration');
                    $environment = new Models\Environment($this->db);
                    $environment->getById($environmentId);
                    if (!$environment->dry()) $this->f3->set('SESSION.collaboration', $environment->collaboration);
                }
                echo \Template::instance()->render('layout.htm');
            }

            // if($this->checkLogin() || $this->checkPublicAccess($this->f3->get("SESSION.environment_id"))){
            //     echo \Template::instance()->render('layout.htm');
            // }else{
            //     echo \Template::instance()->render('index.htm');
            // }
        } else {
            $output = json_encode($this->f3->get('output'));
            //route logging
            $route = $this->f3->get('PARAMS.0');
            $route = str_ireplace($this->f3->get('PARAMS.id'), '', $route);
            if (in_array($route, $this->routeLogging) && $this->f3->exists('SESSION.user.id')) {
                $userLog = new Models\UserLog($this->db);
                $userLog->addEntry([
                    'user_id' => $this->f3->get("SESSION.user.id"),
                    'action' => $route,
                    'environment_id' => $this->f3->get("SESSION.environment_id"),
                    'user_agent' => $this->f3->get('AGENT'),
                    'ip' => $this->f3->get('IP'),
                    'request' => $this->f3->get('BODY'),
                    'response' => $output
                ]);
            }
            header('Content-Type: application/json');
            echo $output;
        }
    }

    /**
     * Modern browser check
     *
     * @return boolean
     */
    public function modernBrowser()
    {
        if ($this->f3->exists('AGENT') && (preg_match('~MSIE|Internet Explorer~i', $this->f3->get('AGENT')) || preg_match('~Trident/7.0(; Touch)?; rv:11.0~', $this->f3->get('AGENT')))) {
            //is IE 11 or below
            return false;
        }
        return true;
    }

    /**
     * Function to replace other role checks
     *
     * @param [text] $property
     * @return void
     */
    public function hasPermission(string $property)
    {
        return $this->f3->get('SESSION.user.authorisation.' . $property);
    }

    /**
     * Check if given project environment id exists
     *
     * @param integer $environmentId
     * @return boolean
     */
    public function checkEnvironmentExists($environmentId)
    {
        // Check if exists
        $environment = new Models\Environment($this->db);
        $environment->getById($environmentId);

        if ($environment->dry()) {
            return false;
        }

        return true;
    }

    /**
     * Check if there is public access to the given environment
     *
     * @param [integer] $environmentId
     * 
     * @return boolean
     */
    public function checkPublicAccess($environmentId)
    {

        // Check guest login
        $environment = new Models\Environment($this->db);
        $environment->load(['id=? AND public_access=1 AND deleted_at is null', $environmentId]);

        if (!$environment->dry()) {
            return true;
        }

        return false;
    }

    /**
     * Check if there is an existing user session
     *
     * @return boolean
     */
    public function checkLogin($guest = false)
    {
        if (!$guest && $this->f3->exists('SESSION.user.id')) {
            return true;
        } else if ($guest) {
            return true;
        }
        return false;
    }

    /**
     * Check if there is an existing user session
     *
     * @return boolean
     */
    public function checkCollaboration()
    {
        if ($this->f3->get('SESSION.collaboration')) {
            return true;
        }
        return false;
    }

    /**
     * Check if there is an existing user session
     *
     * @return boolean
     */
    public function checkVirtualProjectRoomAuthorization()
    {
        if ($this->f3->exists('SESSION.contract')) {
            if ($this->f3->get('SESSION.contract') == 'basisplus' || $this->f3->get('SESSION.contract') == 'business') {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if there is an existing user session
     *
     * @return boolean
     */
    public function checkRelaticsConnectionAuthorization()
    {
        if ($this->f3->exists('SESSION.contract')) {
            if ($this->f3->get('SESSION.contract') == 'basisplus' || $this->f3->get('SESSION.contract') == 'business') {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if there is an existing user session
     *
     * @return boolean
     */
    public function checkPublicViewerAuthorization()
    {
        if ($this->f3->exists('SESSION.contract')) {
            if ($this->f3->get('SESSION.contract') == 'basisplus' || $this->f3->get('SESSION.contract') == 'business') {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if there is an existing user session
     *
     * @return boolean
     */
    public function checkPublicReactionAuthorization()
    {
        if ($this->f3->exists('SESSION.contract')) {
            if ($this->f3->get('SESSION.contract') == 'business') {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if there is an existing user session
     *
     * @return boolean
     */
    public function checkRoLoketAuthorization()
    {
        if ($this->f3->exists('SESSION.contract')) {
            if ($this->f3->get('SESSION.contract') == 'business') {
                return true;
            }
        }
        return false;
    }

    // TODO 30-05-2022 MME: deze methode moet weer verwijderd worden, evenals de aanpassing in route.ini en encryption.html
    public function encryptUserData()
    {
        $userController = new Controllers\User();
        $all = $userController->all();
        $user = new Models\User($this->db);
        foreach ($all as $item) {
            $user->getByIdUnencrypted($item);
            $user->encryptData();
            $user->update();
            $user->getById($item);
            echo ($user->name . '<br>');
            echo ($user->email . '<br>');
            echo ($user->phone . '<br>');
        }
        $reactionNoteController = new Controllers\EnvironmentReaction();
        $all = $reactionNoteController->all();
        $reaction = new Models\EnvironmentReaction($this->db);
        foreach ($all as $item) {
            $reaction->getByIdUnencrypted($item);
            $reaction->name = Toolbox::encryptString($reaction->name);
            $reaction->email = Toolbox::encryptString($reaction->email);
            $reaction->address = Toolbox::encryptString($reaction->address);
            $reaction->phone = Toolbox::encryptString($reaction->phone);
            $reaction->update();
        }
    }

    // TODO 30-05-2022 MME: deze methode moet weer verwijderd worden, evenals de aanpassing in route.ini en userinformation.html
    public function decryptUserData()
    {
        $userController = new Controllers\User();
        $all = $userController->all();
        $user = new Models\User($this->db);
        foreach ($all as $item) {
            $user->getByIdUnencrypted($item);
            $user->decryptData();
            $user->update();
            $user->getById($item);
            echo ($user->name . '<br>');
            echo ($user->email . '<br>');
            echo ($user->phone . '<br>');
        }
        $reactionNoteController = new Controllers\EnvironmentReaction();
        $all = $reactionNoteController->all();
        $reaction = new Models\EnvironmentReaction($this->db);
        foreach ($all as $item) {
            $reaction->getByIdUnencrypted($item);
            $reaction->name = Toolbox::decryptString($reaction->name);
            $reaction->email = Toolbox::decryptString($reaction->email);
            $reaction->address = Toolbox::decryptString($reaction->address);
            $reaction->phone = Toolbox::decryptString($reaction->phone);
            $reaction->update();
        }
    }

    /* 
    * Encrypt also archived and not active users
    */
    public function encryptUserData2()
    {
        $userController = new Controllers\User();
        $all = $userController->all();
        $user = new Models\User($this->db);
        foreach ($all as $item) {
            $user->getDeletedByIdUnencrypted($item);
            if (isset($user->id)) {
                echo ($user->id . '<br>');
                echo ($user->name . '<br>');
                echo ($user->email . '<br>');
                echo ($user->phone . '<br>');
                echo ($user->deleted_at . '<br>');
                $user->encryptData();
                $user->update();
                $user->getById($item);
                echo ($user->name . ' encrypted.<br><br>');
            }
        }
    }

    /**
     * Fetches all azure groups that a user is part of
     * Max number of groups per memberOf call is 100, so if there are more go to nextLink
     * 
     * If there are groups the user is part of, return group array
     * If there are no groups the user is part of, return empty groups array
     *
     * @return array
     */
    private function fetchAllAzureGroups($authToken)
    {
        $groups = [];
        $nextLink = "https://graph.microsoft.com/v1.0/me/memberOf?\$top=100";

        do {
            $options = array(
                "http" => array(
                    "method" => "GET",
                    "header" => "Accept: application/json\r\n" .
                        "Authorization: Bearer " . $authToken . "\r\n"
                )
            );
            $context = stream_context_create($options);
            $response = @file_get_contents($nextLink, false, $context);
            if ($response === FALSE) {
                // Handle error; break or return
                return $groups;
            }

            $data = json_decode($response, true);
            $groups = array_merge($groups, $data['value']);

            $nextLink = $data['@odata.nextLink'] ?? null;
        } while ($nextLink);

        return $groups;
    }

    /**
     * Login through azure
     *
     * @return void
     */
    public function azureLogin()
    {
        $this->f3->clear('SESSION.azureFailed');
        $this->f3->set('SESSION.azurelogin', 'true');

        $client_id = $this->f3->get('azure.client_id');
        $client_secret = $this->f3->get('azure.client_secret');
        $client_redirect_url = $this->f3->get('azure.client_redirect_url');

        $redirect_uri = urlencode($client_redirect_url . '/azure/login');

        if (!isset($_GET["code"]) and !isset($_GET["error"])) {
            //Real authentication part begins
            $url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?";
            $url .= "state=" . session_id();  //This at least semi-random string is likely good enough as state identifier
            $url .= "&scope=profile+openid+email+offline_access+User.Read+Group.Read.All"; // if you like
            $url .= "&response_type=code";
            $url .= "&approval_prompt=auto";
            $url .= "&client_id=" . $client_id;
            $url .= "&redirect_uri=" . $redirect_uri;
            header("Location: " . $url);  //So off you go my dear browser and welcome back for round two after some redirects at Azure end

        } elseif (isset($_GET["error"])) {  //Second load of this page begins, but hopefully we end up to the next elseif section...
            $this->f3->set('SESSION.failed', 1);
            $this->f3->reroute('/');
            $this->f3->error(401, 'Geen toegang');
        } elseif (strcmp(session_id(), $_GET["state"]) == 0) {  //Checking that the session_id matches to the state for security reasons

            //Verifying the received tokens with Azure and finalizing the authentication part
            $content = "grant_type=authorization_code";
            $content .= "&client_id=" . $client_id;
            $content .= "&redirect_uri=" . $redirect_uri;
            $content .= "&code=" . $_GET["code"];
            $content .= "&client_secret=" . $client_secret;
            $content .= "&scope=profile+openid+email+offline_access+User.Read+Group.Read.All";
            $options = array(
                "http" => array(  //Use "http" even if you send the request with https
                    "method"  => "POST",
                    "header"  => "Content-Type: application/x-www-form-urlencoded\r\n" .
                        "Content-Length: " . strlen($content) . "\r\n",
                    "content" => $content
                )
            );
            $context  = stream_context_create($options);
            $json = file_get_contents("https://login.microsoftonline.com/common/oauth2/v2.0/token", false, $context);

            $authdata = json_decode($json, true);

            //Fetching the basic user information that is likely needed by your application
            $options = array(
                "http" => array(  //Use "http" even if you send the request with https
                    "method" => "GET",
                    "header" => "Accept: application/json\r\n" .
                        "Authorization: Bearer " . $authdata["access_token"] . "\r\n"
                )
            );
            $context = stream_context_create($options);
            $json = file_get_contents("https://graph.microsoft.com/v1.0/me", false, $context);

            $userdata = json_decode($json, true);  //This should now contain your logged on user information

            $groupdata = $this->fetchAllAzureGroups($authdata["access_token"]);

            if (!isset($groupdata) || count($groupdata) < 1) {

                $userLog = new Models\UserLog($this->db);
                // Create the user
                $user = new Models\User($this->db);
                $user->getByEmail($userdata["mail"]);

                if (!$user->dry()) {
                    $user->activate($user->id);
                    $this->f3->set('SESSION.guest', false);
                    $this->f3->set('SESSION.user', [
                        'id'            => $user->id,
                        'email'         => $user->email,
                        'name'          => $user->name,
                        'role'          => [],
                        'authorisation' => [],
                        'job_title'     => $user->job_title,
                        'phone'         => $user->phone,
                        'mailings'      => $user->mailings
                    ]);

                    $userLog->addEntry([
                        'user_id'       => $user->id,
                        'action'        => 'logged-in',
                        'user_agent'    => $this->f3->get('AGENT'),
                        'ip'            => $this->f3->get('IP')
                    ]);
                    // Delete records from user log table when successfull login
                    $userLog->erase(['user_id=? AND ip=? AND `action`="login-failed"', $user->id, $this->f3->get('IP')]);

                    $this->f3->clear('SESSION.failed');
                    $this->f3->reroute('/');
                } else {
                    $this->f3->set('SESSION.azureFailed', 1);
                    $this->f3->reroute('/');
                    $this->f3->error(401, 'Geen toegang');
                }
            }

            $domain = strstr($userdata["userPrincipalName"], '@'); // Returns "@example.com"
            $domain = substr($domain, 1); // Removes the "@" symbol

            // Get company by name
            $company = new Models\Company($this->db);
            $company->getByAzureDomainName($domain);

            if (!$company->dry()) {

                $userLog = new Models\UserLog($this->db);
                // Create the user
                $user = new Models\User($this->db);
                $user->getByEmailAuthType($userdata['mail'], 'sso');

                if (!$user->dry()) {
                    $user->activate($user->id);

                    $this->f3->set('SESSION.guest', false);
                    $this->f3->set('SESSION.PHPID', $this->f3->get('COOKIE.PHPSESSID'));

                    $data = [
                        'id'            => $user->id,
                        'email'         => $user->email,
                        'name'          => $user->name,
                        'role'          => $user->role,
                        'authorisation' => [],
                        'job_title'     => $user->job_title,
                        'phone'         => $user->phone,
                        'mailings'      => $user->mailings
                    ];

                    $this->f3->set('SESSION.user', $data);

                    // add to user_log after successfull login
                    $userLog->addEntry([
                        'user_id'       => $user->id,
                        'action'        => 'azure-logged-in',
                        'user_agent'    => $this->f3->get('AGENT'),
                        'ip'            => $this->f3->get('IP')
                    ]);

                    // Delete records from user log table when successfull login
                    $userLog->erase(['user_id=? AND ip=? AND `action`="login-failed"', $user->id, $this->f3->get('IP')]);
                    // clear error flag
                    $this->f3->clear('SESSION.failed');
                    $this->f3->clear('SESSION.failed');
                } else {
                    $user->copyFrom([
                        'email'         => $userdata['mail'],
                        'name'          => $userdata['givenName'] . (!empty($userdata['surname']) ? ' ' . $userdata['surname'] : ''),
                        'job_title'     => $userdata['jobTitle'],
                        'phone'         => $userdata['mobilePhone'],
                        'mailings'      => 0,
                        'active'        => 1,
                        'auth_type'     => 'sso'
                    ]);
                    $user->encryptData();
                    $user->save();

                    $user->decryptData();

                    $userLog->addEntry([
                        'user_id'       => $user->id,
                        'action'        => 'azure-logged-in-no-company',
                        'user_agent'    => $this->f3->get('AGENT'),
                        'ip'            => $this->f3->get('IP')
                    ]);
                }

                $userId = $user->id;

                $sql = "DELETE FROM user_authorisation WHERE user_id=?";
                $this->db->exec($sql, $userId);
                if (isset($groupdata) && count($groupdata) > 1) {
                    // Insert record to user authorisation table maar dit doen we alleen waarbij de groepid ook voorkomt in de tabel environments
                    foreach ($groupdata as $group) {
                        $azureAuthorisation = new Models\AzureAuthorisation($this->db);
                        $azureAuthorisationData = $azureAuthorisation->getAzureGroupsById($group['id']);

                        foreach ($azureAuthorisationData as $auth) {
                            $azureProfileId = $auth['user_profile_id'];
                            $azureCompanyId = $auth['company_id'];
                            $azureProjectId = $auth['project_id'];
                            $azureEnvironmentId = $auth['environment_id'];

                            $sql = "INSERT INTO user_authorisation SET user_id=?, user_profile_id=?, company_id=?, project_id=?, environment_id=? ";

                            $this->db->exec($sql, [$userId, $azureProfileId, $azureCompanyId, $azureProjectId, $azureEnvironmentId]);
                        };
                    }

                    $this->f3->set('SESSION.user', $user->cast());
                    $this->f3->reroute('/');
                } else {
                    $this->f3->clear('SESSION');
                    $this->f3->set('SESSION.azureFailed', 1);
                    $this->f3->reroute('/');
                    $this->f3->error(401, 'Geen toegang');
                }
            } else {

                $userLog = new Models\UserLog($this->db);
                // Create the user
                $user = new Models\User($this->db);
                $user->getByEmail($userdata["mail"]);

                if (!$user->dry()) {
                    $user->activate($user->id);
                    $this->f3->set('SESSION.guest', false);
                    $this->f3->set('SESSION.user', [
                        'id'            => $user->id,
                        'email'         => $user->email,
                        'name'          => $user->name,
                        'role'          => [],
                        'authorisation' => [],
                        'job_title'     => $user->job_title,
                        'phone'         => $user->phone,
                        'mailings'      => $user->mailings
                    ]);

                    $userLog->addEntry([
                        'user_id'       => $user->id,
                        'action'        => 'logged-in',
                        'user_agent'    => $this->f3->get('AGENT'),
                        'ip'            => $this->f3->get('IP')
                    ]);
                    // Delete records from user log table when successfull login
                    $userLog->erase(['user_id=? AND ip=? AND `action`="login-failed"', $user->id, $this->f3->get('IP')]);

                    $this->f3->clear('SESSION.failed');
                    $this->f3->reroute('/');
                } else {
                    $this->f3->set('SESSION.azureFailed', 1);
                    $this->f3->reroute('/');
                    $this->f3->error(401, 'Geen toegang');
                }
            }
        } else {
            //If we end up here, something has obviously gone wrong... Likely a hacking attempt since sent and returned state aren't matching and no $_GET["error"] received.
            echo "Hey, please don't try to hack us!\n\n";
            //echo "PHP Session ID used as state: " . session_id() . "\n";  //And for production version you likely don't want to show these for the potential hacker
            //var_dump($_GET);  //But this being a test script having the var_dumps might be useful
            //errorhandler(array("Description" => "Likely a hacking attempt, due state mismatch.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION), $error_email);
        }
        exit;
    }

    /**
     * Login functionality
     *
     * @return void
     */
    public function login()
    {
        $this->f3->clear('SESSION.azureFailed');
        if ($this->f3->get('SESSION.failed') >= $this->loginFailedLimit) {
            $this->f3->error(429);
        }

        $this->f3->set('SESSION.azurelogin', 'false');
        $userLog = new Models\UserLog($this->db);

        $this->f3->set('SESSION.user', []);

        $email = $this->f3->get('POST.email');
        $password = $this->f3->get('POST.password');

        if (!empty($email) && !empty($password)) {
            $user = new Models\User($this->db);
            $user->getByEmail($email);

            if (!$user->dry()) {
                if (empty($user->password)) {
                    $this->f3->error(401);
                }
                if (PasswordStorage::verify_password($password, $user->password)) {
                    $user->activate($user->id);
                    $this->f3->set('SESSION.guest', false);
                    $this->f3->set('SESSION.user', [
                        'id'            => $user->id,
                        'email'         => $user->email,
                        'name'          => $user->name,
                        'role'          => [],
                        'authorisation' => [],
                        'job_title'     => $user->job_title,
                        'phone'         => $user->phone,
                        'mailings'      => $user->mailings
                    ]);

                    $userLog->addEntry([
                        'user_id'       => $user->id,
                        'action'        => 'logged-in',
                        'user_agent'    => $this->f3->get('AGENT'),
                        'ip'            => $this->f3->get('IP')
                    ]);
                    // Delete records from user log table when successfull login
                    $userLog->erase(['user_id=? AND ip=? AND `action`="login-failed"', $user->id, $this->f3->get('IP')]);

                    $this->f3->clear('SESSION.failed');
                    $this->f3->reroute('/');
                } else {
                    $userLog->addEntry([
                        'user_id' => $user->id,
                        'action' => 'login-failed',
                        'user_agent' => $this->f3->get('AGENT'),
                        'ip' => $this->f3->get('IP')
                    ]);
                    $loginCount = $userLog->count(['user_id=? AND ip=? AND `action`="login-failed" AND created_at > (now() - interval 10 minute)', $user->id, $this->f3->get('IP')]);
                    $this->f3->set('SESSION.failed', $loginCount);
                    $this->f3->reroute('/');
                }
            } else {
                $loginCount = $this->f3->get('SESSION.failed');
                if (empty($loginCount)) $loginCount = 0;
                $loginCount++;
                $this->f3->set('SESSION.failed', $loginCount);
                $this->f3->reroute('/');
            }
        }
    }

    public function index()
    {
    }

    /**
     * Clear the current session and logout
     *
     * @return void
     */
    public function logout()
    {
        if ($this->f3->get('SESSION.user.id')) {
            $user = new Models\User($this->db);
            $user->getById($this->f3->get('SESSION.user.id'));
            if (!$user->dry()) {
                $userLog = new Models\UserLog($this->db);
                $userLog->addEntry([
                    'user_id' => $user->id,
                    'environment_id' => $this->f3->get('SESSION.environment_id'),
                    'action' => 'logged-out',
                    'user_agent' => $this->f3->get('AGENT'),
                    'ip' => $this->f3->get('IP')
                ]);
            }
        }

        $this->f3->set('output', []);
        $this->f3->clear('SESSION');
        $this->f3->reroute('/');
        session_destroy();
    }

    /**
     * Reset user password
     *
     * @return void
     */
    public function forgotPassword()
    {
        // Render token
        if ($this->f3->exists('GET.email', $email)) {

            $token = $this->f3->get('GET.token');
            $csrf = $this->f3->get('SESSION.PIMCSRF');

            if ($token !== $csrf) {
                $this->f3->error(428, 'Er is een probleem opgetreden! Neem aub contact op met helpdesk@pim.info');
            }

            $userLog = new Models\UserLog($this->db);

            $user = new Models\User($this->db);
            $user->getByEmail($email);
            if (!$user->dry()) {
                if ($user->auth_type === 'sso') {
                    $loginCount = $this->f3->get('SESSION.azureFailed');
                    if (empty($loginCount)) $loginCount = 0;
                    $loginCount++;
                    $this->f3->set('SESSION.azureFailed', $loginCount);
                } else {
                    // set token
                    $user->token = Toolbox::getToken();
                    $user->password = NULL;
                    $user->encryptData();
                    $user->save();

                    $userLog->addEntry([
                        'user_id' => $user->id,
                        'action' => 'forgotpassword',
                        'environment_id' => $this->f3->get("SESSION.environment_id"),
                        'user_agent' => $this->f3->get('AGENT'),
                        'ip' => $this->f3->get('IP'),
                        'request' => $this->f3->get('BODY')
                    ]);
                    $user->decryptData();
                    // Mail password reset with token
                    $this->f3->get('mailWrapper')->send([
                        'to'      => $user->email,
                        'action-url' => '/passwordreset?token=' . $user->token . '&email=' . $user->email,
                        'body' => 'Klik op onderstaande knop om een nieuw wachtwoord te kiezen.',
                        'title' => 'Wachtwoord reset',
                        'name' => $user->name,
                        'template' => 5
                    ]);

                    $this->f3->reroute('/passwordreset-success');
                }
            }
        }
        $this->f3->reroute('/');
    }

    /**
     * Password reset
     *
     * @return void
     */
    public function passwordReset()
    {
        $this->f3->clear('SESSION');
        $userLog = new Models\UserLog($this->db);
        // Get token and verify email
        $user = new Models\User($this->db);

        if ($this->f3->exists('GET.token') && $this->f3->exists('GET.email') && $this->f3->exists('POST.passwordreset')) {
            $email = $this->f3->get('GET.email');
            $token = $this->f3->get('GET.token');
            $password = $this->f3->get('POST.passwordreset');

            $user->getByEmailAndToken($email, $token);

            if (!$user->dry() && !empty($password)) {
                $user->password = PasswordStorage::create_hash($password);
                $user->token = null;
                $user->active = 1;
                $user->encryptData();
                $user->save();

                $userLog->addEntry([
                    'user_id' => $user->id,
                    'action' => 'password-success',
                    'environment_id' => $this->f3->get("SESSION.environment_id"),
                    'user_agent' => $this->f3->get('AGENT'),
                    'ip' => $this->f3->get('IP'),
                ]);

                $this->f3->set('output', ['message' => 'Password changed successfully']);

                $user->decryptData();
                // Send mail with password reset notification
                $this->f3->get('mailWrapper')->send([
                    'to'      => $user->email,
                    'action-url' => '',
                    'name' => $user->name,
                    'template' => 6,
                    'body' => 'Wachtwoord succesvol gewijzigd',
                    'title' => 'Wachtwoord succesvol gewijzigd'
                ]);

                $this->f3->reroute('/');
            }
        }
        echo \Template::instance()->render('passwordreset-form.htm');
        exit;
    }

    public function passwordResetSuccess()
    {
        echo \Template::instance()->render('passwordreset-success.htm');
        exit;
    }

    public function testEmbedded()
    {
        echo \Template::instance()->render('testembedded.htm');
        exit;
    }

    public function terms()
    {
        echo \Template::instance()->render('algemenevoorwaardenendisclaimer.htm');
        exit;
    }

    public function privacy()
    {
        echo \Template::instance()->render('privacyverklaring.htm');
        exit;
    }

    public function publicViewers()
    {
        echo \Template::instance()->render('public.htm');
        exit;
    }

    public function help()
    {
        echo \Template::instance()->render('help.htm');
        exit;
    }

    public function userManualPdf()
    {
        $web = \Web::instance();
        if ($this->checkLogin()) {
            $filepath = 'ui/Gebruikers handleiding pimplatform.pdf';
        } else {
            $filepath = 'ui/Gebruikers handleiding openbaar pimplatform.pdf';
        }
        $sent = $web->send($filepath);
        exit;
    }

    /**
     * Debug 
     *
     * @return void
     */
    public function debug()
    {

        if ($this->checkLogin() && $this->f3->get('DEBUG')) {

            echo '<pre>';
            var_dump($this->f3->get('SESSION'));
            //phpinfo();

        } else {
            echo 'na';
        }
        exit;
    }

    /**
     * Backwards compatible function to download source files
     *
     * @return void
     */

    // TODO 10-08-2022 MME: lijkt dode code te zijn
    public function downloadSourcefile()
    {
        if ($this->checkLogin()) {
            if ($this->f3->exists('GET.filename')) {
                $filePath = $this->f3->get('SOURCEFILES') . '/' . $this->f3->get('GET.filename');
                if (file_exists($filePath) && is_file($filePath)) {
                    $web = \Web::instance();
                    if ($this->f3->get('PARAMS.type') == 'view') {
                        header('Content-Type: ' . $web->mime($filePath));
                        readfile($filePath);
                    } else {
                        $sent = $web->send($filePath);
                    }
                    // if ( !$sent)  { /*error*/ }
                    exit;
                } else {
                    $this->f3->error(404);
                }
            } else {
                $this->f3->error(404);
            }
        } else {
            $this->f3->error(401);
        }
    }

    /**
     * Share messages with or without files through email
     *
     * @return void
     */
    public function shareMessage()
    {

        //var_dump($this->f3->get('POST.sharetype'));
        //die('fdsgdsfgdsg');

        if ($this->checkLogin()) {
            if (empty($this->f3->get('POST.user_id'))) {
                $this->f3->error(400, $this->f3->get('message.missing.users'));
            }
            $sharetype = $this->f3->get('POST.sharetype');

            $user = new Models\User($this->db);
            $environment = new Models\Environment($this->db);

            $subject = $this->f3->get('POST.subject');
            $text = $this->f3->get('POST.text');

            $url = $this->f3->get('POST.url');

            $environmentId = $this->f3->get('POST.environment_id');

            $recipients = $mailVariables = [];
            foreach ($this->f3->get('POST.user_id') as $userId) {
                $user->getById($userId);
                if (!$user->dry()) {
                    $recipients[$user->email] = $user->cast();

                    if (!empty($environmentId)) {
                        $mailVariables['template'] = 30;

                        $pimBox = new Controllers\PimBox();
                        if ($this->f3->exists('POST.filename') && !empty($this->f3->get('POST.filename'))) {
                            //share file
                            $mailVariables['template'] = 11;
                            if (empty($this->f3->get('POST.path'))) {
                                //share mytransfer with PIM
                                $pimBox->shareFile($this->f3->get('POST.filename'), $environmentId, $userId);
                            }
                        }

                        $environment->getById($environmentId);
                        if (!$environment->dry()) {
                            $mailVariables['environment_id'] = $environmentId;
                            $mailVariables['environment_name'] = $environment->name;
                        }

                        $recipients[$user->email]['user_id'] = $userId;

                        $mailVariables['receivers'] = array_column($recipients, 'name');
                        $mailVariables['name'] = $user->name;
                        $mailVariables['sender_name'] = $this->f3->get("SESSION.user.name");
                        $mailVariables['to'] = $user->email;
                        $mailVariables['subject'] = $this->f3->get('POST.subject');
                        $mailVariables['body'] = nl2br($this->f3->get('POST.text'));
                        $mailVariables['action-url'] = '?' . $url;
                        if ($this->f3->exists('POST.title')) {
                            $mailVariables['title'] = $this->f3->get('POST.title');
                        }
                        if ($this->f3->exists('POST.action-title')) {
                            $mailVariables['action-title'] = $this->f3->get('POST.action-title');
                        }

                        $this->f3->get('mailWrapper')->send($mailVariables);
                    }
                }
            }

            if (count($recipients)) {
                // $mailVariables['recipients'] = $recipients;
                // $this->f3->get('mailWrapper')->send($mailVariables);
            } else {
                $this->f3->error(400, $this->f3->get('message.missing.users'));
            }
            $this->f3->set('output', 'sharesuccess');
        } else {
            $this->f3->error(401);
        }
    }

    /**
     * Render minified files
     *
     * @param [string] $type
     * @param [array] $files
     * @return void
     */
    public function minify($type, $files)
    {
        $path = $this->f3->get('UI') . $type . '/';
        foreach ($files as $file) {
            if (in_array($this->f3->get('ENVIRONMENT'), ['live', 'acceptance'])) {
                $filename = $path . $file;
                if (!file_exists($filename)) {
                    return;
                }
                $newFile = str_replace('.js', '.min.js', $filename);

                $minifiedCode = \JShrink\Minifier::minify($this->f3->read($path . $file));
                $this->f3->write($newFile, $minifiedCode);

                \Classes\Toolbox::removeFile($filename, true);
            }
        }
    }

    /**
     * Verify google recaptcha
     *
     * @return void
     */
    public function recaptchaVerification($token)
    {
        $recaptcha = new \ReCaptcha\ReCaptcha($this->f3->get('google.secret'));
        $resp = $recaptcha->setExpectedHostname($this->f3->get('HOST'))
            ->setScoreThreshold(0.5)
            ->verify($token, $this->f3->get('IP'));
        if ($resp->isSuccess()) {
            return true;
        } else {
            return false;
        }
    }
}
