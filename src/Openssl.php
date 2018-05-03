<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2018/5/3 0003
 * Time: 10:33
 */
namespace shangxin\openssl;

use yii\base\Component;

class Openssl extends Component{

    /**
     * @var string the name of the root path
     */
    public $verify_path;

    /**
     * @var string the name of the private key file
     * openssl_private_key.pem
     */
    public $private_key_file_name;

    /**
     * @var string the name of the public key file
     * openssl_public_key.pem
     */
    public $public_key_file_name;

    /**
     * @var array   openssl config
     */
    public $config=[
//        'private_key_bits'=>1024,
//        "private_key_type" => OPENSSL_KEYTYPE_RSA,
//        'config'=>'F:\phpstudy\PHPTutorial\Apache\conf\openssl.cnf'
    ];


    /**
     * openssl生成公钥私钥
     * @throws \Exception
     */
    public function generate_key(){
        try{
            $extension = extension_loaded('openssl');
            if(!$extension){
                throw new \Exception('the extension of openssl not exist!');
            }
            $resource = openssl_pkey_new($this->config);
            if(!$resource){
                throw new \Exception(openssl_error_string());
            }
            openssl_pkey_export($resource,$privateKey,null,$this->config);
            $private_key_path = $this->verify_path.$this->private_key_file_name;

            $fp_private = fopen($private_key_path,'w');
            fwrite($fp_private,$privateKey);
            fclose($fp_private);

            $pubKey = openssl_pkey_get_details($resource);
            $public_key_path = $this->verify_path.$this->public_key_file_name;

            $fp_public = fopen($public_key_path,'w');
            fwrite($fp_public,$pubKey["key"]);
            fclose($fp_public);

        }catch (\Exception $e){
            throw new \Exception($e->getMessage());
        }
    }

    /**
     * 私钥解密
     * @param $params_str
     * @return mixed
     */
    public function verifyParams($params_str){
//        $private_key = file_get_contents($this->verify_path.$this->private_key_file_name);
//        openssl_private_decrypt(base64_decode($params_str),$decrypt,$private_key);
//        return $decrypt;
        $public_key = file_get_contents($this->verify_path.$this->public_key_file_name);
        openssl_public_decrypt(base64_decode($params_str),$decrypt,$public_key);
        return $decrypt;
    }

    /**
     * 私钥加密
     * @param $params
     * @return string
     * @throws \Exception
     */
    public function signParams($params){
        $sign_str = '';
        if(is_string($params) && $params!=''){
            $sign_str = $params;
        }
        if(is_array($params) && count($params)>0){
            $sign_str = self::params_parse($params);
        }
        if($sign_str == ''){
            throw new \Exception('代签名数据不能为空');
        }
        $private_key = file_get_contents($this->verify_path.$this->private_key_file_name);
        openssl_private_encrypt($sign_str,$encrypt,$private_key);
        return base64_encode($encrypt);
    }

    /**
     * 代签名数据数组转字符串
     * @param array $params
     * @return string
     * @throws \Exception
     */
    public static function params_parse($params = array()){
        if(!count($params)>0){
            throw new \Exception('代签名数组不能为空');
        }
        $sign_str = '';
        array_walk($params,function($val,$key)use(&$sign_str){
            $sign_str .= $key.'='.$val.'&';
        });
        return mb_substr($sign_str,0,mb_strlen($sign_str)-1);
    }


}