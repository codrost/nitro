<?php

namespace Classes;

use Dompdf\Exception;
use \SimpleXmlElement;

class Toolbox
{

    /*
 * orderen van een array op basis van een property in elk element van een array
 */
    public static function sortArrayByProperty(&$array, $key, $string = false, $asc = true)
    {
        if ($string) {
            usort($array, function ($a, $b) use (&$key, &$asc) {
                if ($asc)    return strcmp(strtolower($a[$key]), strtolower($b[$key]));
                else        return strcmp(strtolower($b[$key]), strtolower($a[$key]));
            });
        } else {
            usort($array, function ($a, $b) use (&$key, &$asc) {
                if ($a[$key] == $b[$key]) {
                    return 0;
                }
                if ($asc) return ($a[$key] < $b[$key]) ? -1 : 1;
                else     return ($a[$key] > $b[$key]) ? -1 : 1;
            });
        }
    }
    /**
     * lees de key en iv voor de encryptie uit de .ini-file, dit kan niet middels de andere techniek
     * met $this->f3->get want deze functies zijn static en hebben geen toegang tot '$this'
     */
    private static function getEncryptionInformation(): array
    {
        $f3 = \Base::instance();
        $iniPath = 'app/config/' . $f3->get('ENVIRONMENT') . '.ini';
        $ini_array = parse_ini_file($iniPath, true);
        $key = $ini_array["encryption"]["key"];
        $iv = $ini_array["encryption"]["iv"];
        return array("key" => $key, "iv" => $iv);
    }

    /**
     * encrypt een string en krijg het versleuteld resultaat terug
     * @param $dataToEncrypt
     * @return string
     */
    public static function encryptString($dataToEncrypt): string
    {
        $encryptionInfo = Toolbox::getEncryptionInformation();
        return openssl_encrypt($dataToEncrypt, "AES-128-CTR", $encryptionInfo["key"], 0, $encryptionInfo["iv"]);
    }

    /**
     * decrypt een versleutelde tekst en krijg leesbare tekst terug
     * @param $dataToDecrypt
     * @return string
     */
    public static function decryptString($dataToDecrypt): string
    {
        $encryptionInfo = Toolbox::getEncryptionInformation();
        try {
            return openssl_decrypt($dataToDecrypt, "AES-128-CTR", $encryptionInfo["key"], 0, $encryptionInfo["iv"]);
        } catch (Exception $e) {
            return $dataToDecrypt;
        }
    }



    /**
     * Get token for password resets
     *
     * @return string
     */
    public static function getToken()
    {
        return md5(uniqid(rand(), TRUE) . 'PimPlatformSalt2019');
    }

    /**
     * Convert to utf8
     *
     * @param [type] $string
     * @return string
     */
    public static function convertUTF8($string)
    {
        if (strlen(utf8_decode($string)) == strlen($string)) {
            // $string is not UTF-8
            return iconv("ISO-8859-1", "UTF-8", $string);
        } else {
            // already UTF-8
            return $string;
        }
    }

    /**
     * 
     * Delete a directory RECURSIVELY
     * @param string $dir - directory path
     * @link http://php.net/manual/en/function.rmdir.php
     */
    public static function rrmdir($dir)
    {
        if (is_dir($dir)) {
            $objects = scandir($dir);
            foreach ($objects as $object) {
                if ($object != "." && $object != "..") {
                    if (filetype($dir . "/" . $object) == "dir") {
                        self::rrmdir($dir . "/" . $object);
                    } else {
                        unlink($dir . "/" . $object);
                    }
                }
            }
            reset($objects);
            rmdir($dir);
        }
    }

    /**
     * Converting soap response to php array
     *
     * @param string $xml
     * @return array
     */
    public static function soapToArray(string $soapXml)
    {
        return json_decode(json_encode((new SimpleXMLElement(preg_replace("/(<\/?)(\w+):([^>]*>)/", "$1$2$3", $soapXml)))), true);
    }

    /**
     * Case
     *
     * @param string $needle
     * @param array $haystack
     * @return boolean
     */
    public static function in_arrayi($needle, $haystack)
    {
        return in_array(strtolower($needle), array_map('strtolower', $haystack));
    }

    /**
     * Undocumented function
     *
     * @param object $xml SimpleXml
     * @param array $options
     * @return array
     */
    public static function xmlToArray($xml, $options = array())
    {
        $defaults = array(
            'namespaceSeparator' => ':', //you may want this to be something other than a colon
            'attributePrefix' => '@',   //to distinguish between attributes and nodes with the same name
            'alwaysArray' => array(),   //array of xml tag names which should always become arrays
            'autoArray' => true,        //only create arrays for tags which appear more than once
            'textContent' => '$',       //key used for the text content of elements
            'autoText' => true,         //skip textContent key if node has no attributes or child nodes
            'keySearch' => false,       //optional search and replace on tag and attribute names
            'keyReplace' => false       //replace values for above search values (as passed to str_replace())
        );
        $options = array_merge($defaults, $options);
        $namespaces = $xml->getDocNamespaces();
        $namespaces[''] = null; //add base (empty) namespace

        //get attributes from all namespaces
        $attributesArray = array();
        foreach ($namespaces as $prefix => $namespace) {
            foreach ($xml->attributes($namespace) as $attributeName => $attribute) {
                //replace characters in attribute name
                if ($options['keySearch']) $attributeName =
                    str_replace($options['keySearch'], $options['keyReplace'], $attributeName);
                $attributeKey = $options['attributePrefix']
                    . ($prefix ? $prefix . $options['namespaceSeparator'] : '')
                    . $attributeName;
                $attributesArray[$attributeKey] = (string)$attribute;
            }
        }

        //get child nodes from all namespaces
        $tagsArray = array();
        foreach ($namespaces as $prefix => $namespace) {
            foreach ($xml->children($namespace) as $childXml) {
                //recurse into child nodes
                $childArray = self::xmlToArray($childXml, $options);
                list($childTagName, $childProperties) = [key($childArray), current($childArray)];

                //replace characters in tag name
                if ($options['keySearch']) $childTagName =
                    str_replace($options['keySearch'], $options['keyReplace'], $childTagName);
                //add namespace prefix, if any
                if ($prefix) $childTagName = $prefix . $options['namespaceSeparator'] . $childTagName;

                if (!isset($tagsArray[$childTagName])) {
                    //only entry with this key
                    //test if tags of this type should always be arrays, no matter the element count
                    $tagsArray[$childTagName] =
                        in_array($childTagName, $options['alwaysArray']) || !$options['autoArray']
                        ? array($childProperties) : $childProperties;
                } elseif (
                    is_array($tagsArray[$childTagName]) && array_keys($tagsArray[$childTagName])
                    === range(0, count($tagsArray[$childTagName]) - 1)
                ) {
                    //key already exists and is integer indexed array
                    $tagsArray[$childTagName][] = $childProperties;
                } else {
                    //key exists so convert to integer indexed array with previous value in position 0
                    $tagsArray[$childTagName] = array($tagsArray[$childTagName], $childProperties);
                }
            }
        }

        //get text content of node
        $textContentArray = array();
        $plainText = trim((string)$xml);
        if ($plainText !== '') $textContentArray[$options['textContent']] = $plainText;

        //stick it all together
        $propertiesArray = !$options['autoText'] || $attributesArray || $tagsArray || ($plainText === '')
            ? array_merge($attributesArray, $tagsArray, $textContentArray) : $plainText;

        //return node as array
        return array(
            $xml->getName() => $propertiesArray
        );
    }

    /**
     * function to remove namespaces from soap string
     *
     * @param string
     * @param [string] $namespaces
     * @return string
     */
    public static function removeNamespaces($content, $namespaces)
    {
        $res = $content;
        foreach ($namespaces as $namespace) {
            $res = str_replace('<' . $namespace . ':', '<', $res);
            $res = str_replace('</' . $namespace . ':', '</', $res);
        }
        return $res;
    }

    /**
     * Remove a file base on a daily bases
     *
     * @param [type] $filename
     * @param integer $days
     * @return bool
     */
    public static function removeFile($filename, $skipInterval = false, $days = 30)
    {
        $currentTime = time();
        $removeInterval = 60 * 60 * 24 * $days;

        if ($skipInterval) {
            unlink($filename);
            return true;
        }
        if (is_file($filename) && $currentTime - filemtime($filename) >= $removeInterval) {
            unlink($filename);
            return true;
        }
        return false;
    }

    /**
     * 
     *
     * 
     */
    public static function unique_multidim_array($array, $key)
    {
        $temp_array = array();
        $i = 0;
        $key_array = array();

        foreach ($array as $val) {
            if (!in_array($val[$key], $key_array)) {
                $key_array[$i] = $val[$key];
                $temp_array[$i] = $val;
            }
            $i++;
        }
        return $temp_array;
    }


    /**
     * 
     *
     * 
     */
    public static function stringContains($array, $string)
    {
        if (empty($string))
            return false;

        //echo strtolower($string) .'-/-'. strtolower($item).'<br>';

        foreach ($array as $item) {
            if (strpos(strtolower($string), strtolower($item)) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Recursive copy directory
     *
     * @param string $source
     * @param string $destination
     * @return void
     */
    public static function recursiveCopy($source, $destination)
    {

        $dir = opendir($source);
        mkdir($destination);
        // return $cc; 
        while (false !== ($file = readdir($dir))) {
            if (($file != '.') && ($file != '..')) {
                if (is_dir($source . '/' . $file)) {
                    self::recursiveCopy($source . '/' . $file, $destination . '/' . $file);
                } else {
                    copy($source . '/' . $file, $destination . '/' . $file);
                }
            }
        }

        closedir($dir);
    }

    /**
     * Merge all files in temp_dir to filename (use for upload in filechuncks)
     *
     * @param string $temp_dir
     * @param string $fileName
     * @param int $chunkSize
     * @param int $totalSize
     * @param int $total_files
     * @return void|bool
     */
    public static function createFileFromChunks($temp_dir, $fileName, $chunkSize, $totalSize, $total_files)
    {

        // count all the parts of this file
        $total_files_on_server_size = 0;
        $temp_total = 0;
        foreach (scandir($temp_dir) as $file) {
            $temp_total = $total_files_on_server_size;
            $tempfilesize = filesize($temp_dir . '/' . $file);
            $total_files_on_server_size = $temp_total + $tempfilesize;
        }
        // check that all the parts are present
        // If the Size of all the chunks on the server is equal to the size of the file uploaded.
        if ($total_files_on_server_size >= $totalSize) {
            // create the final destination file 


            if (($fp = fopen($fileName, 'w+')) !== false) {
                for ($i = 1; $i <= $total_files; $i++) {
                    fwrite($fp, file_get_contents($temp_dir . '/' . $fileName . '.part' . $i));
                    error_log('writing chunk ' . $i);
                }
                fclose($fp);
            } else {
                error_log('cannot create the destination file');
                return false;
            }
        }
    }


    /** general curl request 
     * returns Null if error
     * otherwise returns content as string
     * 
     * @param string $url
     * @param [] $header
     * @param boolean $post  true if post request, default GET
     * @param string $body
     * @return void|string
     * 
     */

    public static function executeCurl(string $url, $header = array('Content-Type: application/json'), $post = false, $body = '')
    {
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_VERBOSE, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        if ($post) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');

            if (isset($body) && strlen($body) > 0) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body); //parameters data   
            } else { // if body is empty then move params from get (url) to post (body)
                $urlparams = explode('?', $url)[1];
                $url = explode('?', $url)[0];
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_POST, count(explode('&', $urlparams))); //number of parameters sent
                curl_setopt($ch, CURLOPT_POSTFIELDS, $urlparams); //parameters data  
            }
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_FAILONERROR, 1);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLINFO_HEADER_OUT, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);

        if (curl_errno($ch)) {
            error_log(curl_error($ch));
            return Null;
        } else {

            //getting response from server
            $response = curl_exec($ch);

            // Split headers
            $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

            $request = curl_getinfo($ch, CURLINFO_HEADER_OUT);
            // Get headers from response
            $header = substr($response, 0, $header_size);
            // Remove headers from response
            $content = substr($response, $header_size);
            return $content;
        }
    }


    /** general curl request as json
     * returns Null if error
     * otherwise returns content as string
     * 
     * @param string $url
     * @param [] $header
     * @param boolean $post  true if post request, default GET
     * @return []
     * 
     */
    public static function executeCurlasJSON(string $url, $header = array('Content-Type: application/json'), $post = false, $body = Null)
    {
        try {
            $result = self::executeCurl($url, $header, $post, $body);
            return json_decode($result, true);
        } catch (Exception $e) {
            return [];
        }
    }
}
