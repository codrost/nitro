<?php

namespace Controllers;

use \base\Controller as BaseController;

class Test extends BaseController
{

    public function test()
    {
        $this->f3->set('output', ['name' => 'test voorbeeld']);
        return true;
    }
}
