<?php
/**
 * This class provides the methods which will allow the server to
 * authenticate with a client user using the TrustAuth addon. The usage
 * of this library is fairly simple.
 *
 * @author Daniel Fox
 * @link foamicate.com
 * @license BSD-3 Clause License http://opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (c) 2012, Daniel Fox
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *     Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *     Neither the name of TrustAuth nor the names of its contributors may be used to endorse or promote products derived from this software
 *         without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Dependencies:
 *
 * This class depends on the Crypt/RSA phpseclib found at
 *     http://phpseclib.sourceforge.net
 *
 * There are two main structures used with this API. First is the user
 * array which consists of the following information:
 *      $user = array(
 *          'random'     => // the provided random value
 *          'public_key' => // the public key associated with this user
 *
 *          // The next two are needed only after the challenge is sent
 *          // and are supplied by TrustAuth to you
 *          'md5'        => // the md5 hash response to the challenge
 *          'sha'        => // the sha1 hash response to the challenge
 *      );
 *
 * The other main structure is the server information. This is generated
 * for you and returned as part of the array from the get_challenge
 * function. This information will need to be stored to be accessible
 * for the reply request from the addon. The array consists of:
 *      $server = array(
 *          'pre_master_secret' => // the pre_master_secret generated for
 *                                 // this authentication
 *          'random'            => // the random value that was created
 *      );
 *
 * Usage:
 *
 * 1. To get the challenge message to reply to the TrustAuth addon with
 *    call the get_challenge function with the user array like so:
 *
 *      $result = TrustAuth::get_challenge(array(
 *          'random'     => $user_random,
 *          'public_key' => $public_key,
 *      ));
 *
 *    The function returns an array of data as follows:
 *
 *      array(
 *          'status' => // true if the function was successful false
 *                      // otherwise
 *          'json'   => // a json encoded string that should be returned
 *                      // to the TrustAuth addon
 *          'server' => // the array of information to save for the
 *                      // second function call
 *      );
 *
 * 2. After saving the server array return the json string.
 *
 * 3. When TrustAuth replies with the answer to the challenge add the
 *    hashes to the user array should call the authenticate function like
 *    so:
 *
 *    $user['md5'] = $_POST['hashes']['md5'];
 *    $uesr['sha'] = $_POST['hashes']['sha'];
 *    $result = TrustAuth::authenticate($user, $result['server']);
 *
 *    The function returns an array similar to the first:
 *
 *      array(
 *          'status' => // true if the user was authenticated false
 *                      // otherwise
 *          'json'   => // a json encoded string that should be returned
 *                      // to the TrustAuth addon
 *      );
 *
 * 4. No matter whether the authentication was successful or not, the
 *    json string should still be returned to the addon. It will tell the
 *    addon if the authentication was successful or not. If it wasn't,
 *    TrustAuth alerts the user and she can attempt to login again.
 *
 * NOTE:
 *    If either function did not receive the required parameters they
 *    will return false.
 *
 * SEE ALSO:
 *    For an example implementation see foamicate_auth.php
 *
 *
 *
 *
 * Implementation details
 *
 * There are currently 4 status codes. They are:
 *       'auth'          => 0, // Returned with the challenge to indicate
 *                             // the authentication is in progress.
 *       'auth_fail'     => 1, // Returned when the authentication
 *                             // failed.
 *       'logged_in'     => 2, // Returned if the login was successful.
 *       'stage_fail'    => 3, // Indicates that the server and addon are
 *                             // out of sync in the auth process.
 *
 * The general structure of the json array is as follows:
 *
 *      'json' => array(
 *          'status' => // the status code indicating what kind of
 *                      // message this is
 *
 *          // These are required for _fail messages
 *          'error'  => // the error message to display to the user
 *
 *          // These are included in the auth message
 *          'secret' => // the encrypted pre_master_secret
 *          'random' => // the server's random value
 *
 *          // These are incldued in the logged_in and auth_fail
 *          // messages
 *          'url' => // a url to redirect the user's broswer to
 *      )
 *
 * The json returned with the two fail messages should also include an
 * error key with a string to display to the user indicating the
 * problem.
 */

require_once('Crypt/RSA.php');

define("SITE_DOMAIN", $_SERVER['SERVER_NAME']);

class TAException extends Exception {
  private $user_message = '';

  public function __construct($message, $user_message) {
    parent::__construct($message);
    $this->user_message = $user_message;
  }

  public function get_user_message() { return $this->user_message; }
}
class TAResponseExpiredException extends TAException {}
class TAChallengeExpiredException extends TAException {}
class TAHashMismatchException extends TAException {}
class TADomainMismatchException extends TAException {}

class TrustAuth
{
    const CHALLENGE_LENGTH = 64; // in bytes so default is 512 bits
    const HASH_LENGTH = 32; // in bytes so sha 256 returns 32 bytes
    const TIMEOUT = 30; // the maximum length of time to still accept a challenge or response in seconds

    /**
     * Outputs the fields required for a form to allow users to register with TrustAuth.
     *
     * @param {array} $options an array with option values to override the defaults
     * @return {string} string of HTML to output to the page.
     */
    public static function register_form($options) {
      $options = array_merge(array(
        'key_name' => 'ta-key',
        'use_html5' => true,
        'button_class' => '',
      ), $options);

      $str = "<input type=\"hidden\" id=\"trustauth-key\" name=\"" . htmlentities($options['key_name']) . "\"/>\n";
      if ($options['use_html5']) {
        $str.= "<input class=\"" . htmlentities($options['button_class']) . "\" type=\"button\" id=\"trustauth-register\" onclick=\"return false\" value=\"Add TrustAuth Key\"/>";
      } else {
        $str.= "<button id=\"trustauth-register\" class=\"" . htmlentities($options['button_class']) . "\" onclick=\"return false\">Add TrustAuth Key</button>";
      }
      return $str;
    }

    /**
     * Outputs the fields required for a form to be authenticated with TrustAuth.
     *
     * @param {array} $options an array with option values to override the defaults
     * @return {string} string of HTML to output to the page.
     */
    public static function authenticate_form($options) {
      $options = array_merge(array(
        'challenge_name' => 'ta-challenge',
        'response_name' => 'ta-response',
        'key_name' => 'ta-key',
      ), $options);

      if ( ! isset($options['challenge'])) { $options['challenge'] = TrustAuth::get_challenge(); }

      $str = "<input type=\"hidden\" id=\"trustauth-challenge\" name=\"" . htmlentities($options['challenge_name']) . "\" value=\"" . $options['challenge'] . "\"/>\n";
      $str.= "<input type=\"hidden\" id=\"trustauth-response\" name=\"" . htmlentities($options['response_name']) . "\"/>\n";
      $str.= "<input type=\"hidden\" id=\"trustauth-key\" name=\"" . htmlentities($options['key_name']) . "\"/>\n";
      return $str;
    }

    /*
     * This function is to act like a constant array and return the number
     * that corresponds to the correct message type.
     *
     * @param {string} $type the type of message
     * @return {int} the integer corresponding to the message type
     */
    private static function MESSAGE_TYPE($type) {
        $MESSAGE_TYPE = array(
            'challenge' => 0,
            'response'  => 1,
        );
        return $MESSAGE_TYPE[$type];
    }

    /*
     * Generates the challenge message for the client addon.
     *
     * @param user the array of user info, public key, random
     * @returns array of status, json return message and the server values
     *     which will be needed later
     */
    public static function get_challenge() {
        return self::pack_data(
            self::MESSAGE_TYPE('challenge'),
            array(
                'challenge' => self::get_random_value(),
                'domain'    => SITE_DOMAIN,
                'time'      => time(),
            )
        );
    }

    /**
     * The new method for TrustAuth authentication. This function verifies that the encrypted response matches
     * the challenge.
     *
     * @param $challenge the random value used for the challenge that was saved on the server
     * @param $response  the encrypted random value sent by the client
     * @param $public_key the public key to use to decrypt the response with
     * @return true if the decrypted response matches the challenge; false otherwise
     */
    public static function verify($challenge, $response, $public_key) {
        if ( ! isset($challenge) || ! isset($response) || ! isset($public_key) || $challenge == '' || $response == '' || $public_key == '') { return false; }
        set_error_handler('TrustAuth::error_handler');

        $public_key = self::fix_key($public_key);
        $challenge_data = self::unpack_data($challenge);
        $data = self::unpack_data($response);
        $result = false;

        if (self::verify_encrypted_hash($data['calculated_digest'], $data['encrypted_digest'], $public_key)) {
          if ($data['server_hash'] != $challenge_data['hash']) { throw new TAHashMismatchException("Hash from client does not match expected hash.", "Hash mismatch. Try logging in again."); }
          if ($data['domain'] != SITE_DOMAIN) { throw new TADomainMismatchException("Client expected a different domain name.", "Domain mismatch. Try logging in again."); }
          if ($data['time'] + self::TIMEOUT < time()) { throw new TAResponseExpiredException("Response has expired. " . ($data['time'] + self::TIMEOUT) . " < " . time(), "Response expired. Try logging in again."); }
          if ($challenge_data['time'] + self::TIMEOUT < time()) { throw new TAChallengeExpireException("Challenge has expired. " . ($challenge_data['time'] + self::TIMEOUT) . " < " . time(), "Challenge expired. Try logging in again."); }
          $result = true;
        }
        restore_error_handler();
        return $result;
    }

    public static function error_handler($errno, $errstr, $errfile, $errline) {
        if (!(error_reporting() & $errno)) {
            // This error code is not included in error_reporting
            return;
        } else {
            throw new TAException($errstr, "TrustAuth: There was an internal error: $errstr" . "<br/>If the problem persists, you can post a bug report at <a href=\"https://github.com/romaimperator/trustauth-php/issues\">here</a>.");
        }
    }

    /**
     * Generates a random value to use as a challenge for authentication. The length is configurable with
     * the CHALLENGE_LENGTH constant.
     *
     * @return random value
     */
    public static function get_random_value() {
        return bin2hex(openssl_random_pseudo_bytes(self::CHALLENGE_LENGTH));
    }

    /**
     * Converts a UTF-8 encoded string to hex.
     *
     * @param {string} $str the string to convert
     * @return {string} the hex string result
     */
    private static function utf8_to_hex($str) {
        return str_replace("0", "", bin2hex(mb_convert_encoding($str, "8bit", "UTF-8")));
    }

    /**
     * Converts a UTF-8 encoded string to binary.
     *
     * @param {string} $str the string to convert
     * @return {string} the binary string result
     */
    private static function utf8_to_bin($str) {
        return mb_convert_encoding($str, "8bit", "UTF-8");
    }

    /**
     * Converts a hex string to a UTF-8 encoded string.
     *
     * @param {string} $str the string to convert
     * @return {string} the UTF-8 string result
     */
    private static function hex_to_utf8($str) {
        return mb_convert_encoding(pack("H*", $str), "UTF-8", "8bit");
    }


    /**
     * Verifies the signature of the data using the given public key.
     *
     * @param {hex string} $data the encoded data as a hex string
     * @param {string} $public_key the public key to use as a PEM encoded public key
     * @return {bool} true if the signature is valid, false otherwise
     */
    private static function verify_encrypted_hash($calculated_hash, $encrypted_hash, $public_key) {
        if (! isset($calculated_hash) || ! isset($encrypted_hash)) { return false; }

        $rsa = new Crypt_RSA();
        $rsa->loadKey($public_key);
        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);

        $digest = bin2hex($rsa->decrypt(pack("H*", $encrypted_hash)));

        return $digest === $calculated_hash;
    }

    /*
     * Corrects the format of the public key so that Crypt/RSA won't
     * freak out.
     *
     * @param public_key the key
     * @return the fixed key
     */
    private static function fix_key($public_key) {
        $public_key = substr_replace($public_key, '', 0, 26);   // Remove the BEGIN PUBLIC KEY
        $public_key = substr_replace($public_key, '', -24, 24); // Remove the END PUBLIC KEY
        $public_key = str_replace(' ', '', $public_key);        // Remove spaces
        $public_key = str_replace("\r\n", '', $public_key);     // Remove line breaks
        $public_key = chunk_split($public_key, 64, "\r\n");
        return "\r\n-----BEGIN PUBLIC KEY-----\r\n" . $public_key . "-----END PUBLIC KEY-----\r\n";
    }

    /**
     * This function packs the data into a hex string of data in the format for TrustAuth. The type
     * specifies which type of message this is. The data is a hash of data required for the format.
     *
     * Currently there are two formats supported:
     *   challenge => {
     *     'challenge': the random value generated by the server,
     *     'domain'   : the domain name given by the server,
     *     'hash'     : the sha-256 HMAC of the challenge message minus this hash,
     *     'time'     : the unix time in seconds since the epoch this challenge was created,
     *   }
     *
     *   response => {
     *     'challenge': the random value given by the server as the challenge,
     *     'domain'   : domain name of the site,
     *     'hash'     : the hash from the challenge message,
     *     'time'     : the current unix time in seconds since the epoch,
     *   }
     *
     * @param {enum} type the type of message to pack
     * @param {hash} data the data required for the message type
     * @return {string} a hex string of the packed data
     */
    private static function pack_data($type, $data) {
        $b = '';
        if($type == self::MESSAGE_TYPE('challenge')) {
            $b = pack("C", 1);  // Major
            $b .= pack("C", 0); // Minor
            $b .= pack("C", 0); // Patch
            $b .= pack("C", $type);
            $b .= pack("N", $data['time']);
            $encoded_challenge = self::utf8_to_bin($data['challenge']);
            $encoded_domain    = self::utf8_to_bin($data['domain']);
            $b .= pack("n", strlen($encoded_challenge));
            $b .= pack("n", strlen($encoded_domain));
            $b .= $encoded_challenge;
            $b .= $encoded_domain;
            $b .= pack("H*", hash("sha256", bin2hex($b)));
        } else {
            // Unrecognized message type
        }
        return bin2hex($b);
    }

    public static function hex2bin($str) {
      return pack("H*", $str);
    }

    /**
     * This function unpacks data and returns the parts depending on the type of message.
     * See pack_data() for the structure of the hashes.
     *
     * If there is an error a hash is returned with the key 'error' containing the reason
     * for failure.
     *
     * @param {string} $data a hex string encoded in the TrustAuth format
     * @return {hash} the decoded data
     */
    private static function unpack_data($data) {
        $data_copy = $data;
        $version = array(
          'major' => unpack("C", self::hex2bin(substr($data, 0, 2))),
          'minor' => unpack("C", self::hex2bin(substr($data, 2, 2))),
          'patch' => unpack("C", self::hex2bin(substr($data, 4, 2))),
        );
        $version = array(
          'major' => $version['major'][1],
          'minor' => $version['minor'][1],
          'patch' => $version['patch'][1],
        );
        if ($version['major'] != 1 || $version['minor'] != 0 || $version['patch'] != 0) { return array('error' => "Unsupported version number: {$version['major']}.{$version['minor']}.{$version['patch']}"); }
        $data = substr($data, 6);
        $type = unpack("C", self::hex2bin(substr($data, 0, 2)));
        if ($type[1] == self::MESSAGE_TYPE('response')) {
            $time            = unpack("N", self::hex2bin(substr($data, 2, 8)));
            $response_length = unpack("n", self::hex2bin(substr($data, 10, 4)));
            $domain_length   = unpack("n", self::hex2bin(substr($data, 14, 4)));
            $data = substr($data, 18);

            $meta = array(
                'time'            => $time[1],
                'response_length' => $response_length[1],
                'domain_length'   => $domain_length[1],
            );

            $response         = self::hex_to_utf8(substr($data, 0, $meta['response_length'] * 2));
            $data = substr($data, $meta['response_length'] * 2);

            $domain           = self::hex_to_utf8(substr($data, 0, $meta['domain_length'] * 2));
            $data = substr($data, $meta['domain_length'] * 2);

            $server_hash      = substr($data, 0, self::HASH_LENGTH * 2);
            $data = substr($data, self::HASH_LENGTH * 2);

            $digest_length    = unpack("n", self::hex2bin(substr($data, 0, 4)));
            $encrypted_digest = substr($data, 4);

            $calculated_digest = hash("sha256", substr($data_copy, 0, -$digest_length[1] - 4));

            return array(
                'version'           => $version,
                'type'              => $type[1],
                'time'              => $meta['time'],
                'response_length'   => $meta['response_length'],
                'domain_length'     => $meta['domain_length'],
                'response'          => $response,
                'domain'            => $domain,
                'server_hash'       => $server_hash,
                'digest_length'     => $digest_length[1],
                'encrypted_digest'  => $encrypted_digest,
                'calculated_digest' => $calculated_digest,
            );
        } elseif ($type[1] == self::MESSAGE_TYPE('challenge')) {
            $time             = unpack("N", self::hex2bin(substr($data, 2, 8)));
            $challenge_length = unpack("n", self::hex2bin(substr($data, 10, 4)));
            $domain_length    = unpack("n", self::hex2bin(substr($data, 14, 4)));
            $data = substr($data, 18);

            $meta = array(
                'time'             => $time[1],
                'challenge_length' => $challenge_length[1],
                'domain_length'    => $domain_length[1],
            );

            $challege = self::hex_to_utf8(substr($data, 0, $meta['challenge_length'] * 2));
            $data = substr($data, $meta['challenge_length'] * 2);

            $domain = self::hex_to_utf8(substr($data, 0, $meta['domain_length'] * 2));
            $data = substr($data, $meta['domain_length'] * 2);

            $hash = substr($data, 0, self::HASH_LENGTH * 2);

            return array(
                'version'          => $version,
                'type'             => $type[1],
                'time'             => $meta['time'],
                'challenge_length' => $meta['challenge_length'],
                'domain_length'    => $meta['domain_length'],
                'challege'         => $challege,
                'domain'           => $domain,
                'hash'             => $hash,
            );
        } else {
            return array(
                'error' => 'Unrecognized message type',
            );
        }
    }
}
?>
