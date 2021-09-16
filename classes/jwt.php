<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @package auth_cnoauth
 * @author Martin Liao <liaohanzhen@163.com>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2014 onwards Microsoft, Inc. (http://microsoft.com/)
 */

namespace auth_cnoauth;

/**
 * Class for working with JWTs.
 */
class jwt {

    /** @var array Array of JWT header parameters. */
    protected $header = [];

    /** @var array Array of JWT claims. */
    protected $claims = [];

    /**
     * Decode an encoded JWT.
     *
     * @param string $encoded Encoded JWT.
     * @return array Array of arrays of header and body parameters.
     */
    public static function decode($encoded) {
        if (empty($encoded) || !is_string($encoded)) {
            throw new \moodle_exception('errorjwtempty', 'auth_cnoauth');
        }
        $jwtparts = explode('.', $encoded);
        if (count($jwtparts) !== 3) {
            throw new \moodle_exception('errorjwtmalformed', 'auth_cnoauth');
        }

        $header = base64_decode($jwtparts[0]);
        if (!empty($header)) {
            $header = @json_decode($header, true);
        }
        if (empty($header) || !is_array($header)) {
            throw new \moodle_exception('errorjwtcouldnotreadheader', 'auth_cnoauth');
        }
        if (!isset($header['alg'])) {
            throw new \moodle_exception('errorjwtinvalidheader', 'auth_cnoauth');
        }

        $jwsalgs = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'none'];
        if (in_array($header['alg'], $jwsalgs, true) === true) {
            $body = static::decode_jws($jwtparts);
        } else {
            throw new \moodle_exception('errorjwtunsupportedalg', 'auth_cnoauth');
        }

        if (empty($body) || !is_array($body)) {
            throw new \moodle_exception('errorjwtbadpayload', 'auth_cnoauth');
        }

        return [$header, $body];
    }

    /**
     * Decode the payload of a JWS.
     *
     * @param array $jwtparts Array of JWT parts - header and body.
     * @return array|null An array of payload claims, or null if there was a problem decoding.
     */
    public static function decode_jws(array $jwtparts) {
        $body = strtr($jwtparts[1], '-_', '+/');
        $body = base64_decode($body);
        if (!empty($body)) {
            $body = @json_decode($body, true);
        }
        return (!empty($body) && is_array($body)) ? $body : null;
    }

    /**
     * Create an instance of the class from an encoded JWT string.
     *
     * @param string $encoded The encoded JWT.
     * @return \auth_cnoauth\jwt A JWT instance.
     */
    public static function instance_from_encoded($encoded) {
        // debugging(implode($encoded));
        // list($header, $body) = static::decode($encoded);
        $jwt = new static;
        // $jwt->set_header($header);
        // $jwt->set_claims($body);
        $jwt->header = array(
            "typ"=>"JWT",
            "alg"=>"RS256",
            "x5t"=>$encoded['unionid'],
            "kid"=>$encoded['unionid']);
        $jwt->claims = array(
                "aud"=>"b14a7505-96e9-4927-91e8-0601d0fc9caa",
                "iss"=>"https://sts.windows.net/fa15d692-e9c7-4460-a743-29f2956fd429/",
                "iat"=>1536275124,
                "nbf"=>1536275124,
                "exp"=>1536279024,
                "aio"=>"AXQAi/8IAAAAqxsuB+R4D2rFQqOETO4YdXbLD9kZ8xfXadeAM0Q2NkNT5izfg3uwbWSXhuSSj6UT5hy2D6WqApB5jKA6ZgZ9k/SU27uV9cetXfLOtpNttgk5DcBtk+LLstz/Jg+gYRmv9bUU4XlphTc6C86Jmj1FCw==",
                "amr"=>array("rsa"),
                "email"=>"abeli@microsoft.com",
                "family_name"=>"Lincoln",
                "given_name"=>"Abe",
                "idp"=>"https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
                "ipaddr"=>"131.107.222.22",
                "name"=>"abeli",
                "nonce"=>"123523",
                "oid"=>$encoded['unionid'],
                "rh"=>"I",
                "sub"=>"5_J9rSss8-jvt_Icu6ueRNL8xXb8LF4Fsg_KooC2RJQ",
                "tid"=>"fa15d692-e9c7-4460-a743-29f2956fd429",
                "unique_name"=>"AbeLi@microsoft.com",
                "uti"=>"Lxe_46GqTkOpGSfTln4EAA",
                "ver"=>"1.0"
            );
        return $jwt;
    }

    /**
     * Set the JWT header.
     *
     * @param array $params The header params to set. Note, this will overwrite the existing header completely.
     */
    public function set_header(array $params) {
        $this->header = $params;
    }

    /**
     * Set claims in the object.
     *
     * @param array $params An array of claims to set. This will be appended to existing claims. Claims with the same keys will be
     *                      overwritten.
     */
    public function set_claims(array $params) {
        $this->claims = array_merge($this->claims, $params);
    }

    /**
     * Get the value of a claim.
     *
     * @param string $claim The name of the claim to get.
     * @return mixed The value of the claim.
     */
    public function claim($claim) {
        return (isset($this->claims[$claim])) ? $this->claims[$claim] : null;
    }
}
