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

    protected $routeLogging = [];

    public function __construct()
    {
        $f3 = Base::instance();

        // construct database connection
        $connectionString = $f3->get('database.engine') . ':host=' . $f3->get('database.host') . ';port=' . $f3->get('database.port') . ';dbname=' . $f3->get('database.name');
        try {
            $db = new DB\SQL($connectionString, $f3->get('database.username'), $f3->get('database.password'));
        } catch (Exception $e) {
            $f3->reroute('/error/Database niet gevonden<br>Neem contact op met PIMinfo');
        }

        $this->f3 = $f3;
        $this->db = $db;

        $this->db->log(false);

        $this->minify('js', []);

        // example db call
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
     *  basec function which is called by default
     */
    public function index()
    {
    }

    /**
     * Called before route starts
     *
     * @return void
     */
    public function beforeRoute()
    {
        $this->f3->set('output', []);
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
        } else if (gettype($this->f3->get('output')) === 'string') {
            echo $this->f3->get('output');
            //echo \Template::instance()->render('index.html'); */
        } else {
            $output = json_encode($this->f3->get('output'));
            //route logging
            $route = $this->f3->get('PARAMS.0');
            $route = str_ireplace($this->f3->get('PARAMS.id') ?? '', '', $route);
            if (in_array($route, $this->routeLogging) && $this->f3->exists('SESSION.user.id')) {
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
