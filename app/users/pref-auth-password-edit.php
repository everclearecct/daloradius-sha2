<?php
/*
 *********************************************************************************************************
 * daloRADIUS - RADIUS Web Platform
 * Copyright (C) 2007 - Liran Tal <liran@lirantal.com> All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *********************************************************************************************************
 *
 * Authors:    Liran Tal <liran@lirantal.com>
 *             Filippo Lauria <filippo.lauria@iit.cnr.it>
 *
 *********************************************************************************************************
 */

include "library/checklogin.php";
$login_user = $_SESSION["login_user"];

include_once "../common/includes/config_read.php";

include_once "lang/main.php";
include_once "../common/includes/validation.php";
include "../common/includes/layout.php";

// init logging variables
$log = "visited page: ";
$logAction = "";
$logDebugSQL = "";

// if $attribute is a Password attribute,
// return an hashed version of $value
// otherwise false
// if $attribute refers to a non-supported
// hashing method, it just returns $value
function hashPasswordAttribute($attribute, $value)
{
    if (preg_match("/-Password$/", $attribute) === false) {
        return false;
    }
    global $configValues;
    switch ($attribute) {
        case "Crypt-Password":
            return crypt($value, "SALT_DALORADIUS");

        case "MD5-Password":
            return strtoupper(md5($value));

        case "SHA1-Password":
            return sha1($value);

        case "NT-Password":
            return strtoupper(
                bin2hex(mhash(MHASH_MD4, iconv("UTF-8", "UTF-16LE", $value))),
            );

        case "SHA2-Password":
            $hash = hash(
                "sha{$configValues["CONFIG_HASH_SHA_DIGEST_LENGTH"]}",
                $value,
            );
            return "{sha{$configValues["CONFIG_HASH_SHA_DIGEST_LENGTH"]}}{$hash}";
        case "SSHA-224-Password":
            $rand_salt = bin2hex(random_bytes(16));
            $salted_hash = hash("sha224", "{$value}{$rand_salt}");
            $b64coded = base64_encode("{$salted_hash}{$rand_salt}");
            return "{ssha224}{$b64coded}";
        case "SSHA-256-Password":
            $rand_salt = bin2hex(random_bytes(16));
            $salted_hash = hash("sha256", "{$value}{$rand_salt}");
            $b64coded = base64_encode("{$salted_hash}{$rand_salt}");
            return "{ssha256}{$b64coded}";
        case "SSHA-384-Password":
            $rand_salt = bin2hex(random_bytes(16));
            $salted_hash = hash("sha384", "{$value}{$rand_salt}");
            $b64coded = base64_encode("{$salted_hash}{$rand_salt}");
            return "{ssha384}{$b64coded}";
        case "SSHA-512-Password":
            $rand_salt = bin2hex(random_bytes(16));
            $salted_hash = hash("sha512", "{$value}{$rand_salt}");
            $b64coded = base64_encode("{$salted_hash}{$rand_salt}");
            return "{ssha512}{$b64coded}";
        case "SHA3-Password":
            $hash = hash(
                "sha{$configValues["CONFIG_HASH_SHA_DIGEST_LENGTH"]}",
                $value,
            );
            return "{sha3-{$configValues["CONFIG_HASH_SHA_DIGEST_LENGTH"]}}{$hash}";
        case "SSHA3-224-Password":
            $rand_salt = bin2hex(random_bytes(16));
            $salted_hash = hash("sha3-224", "{$value}{$rand_salt}");
            $b64coded = base64_encode("{$salted_hash}{$rand_salt}");
            return "{ssha3-224}{$b64coded}";
        case "SSHA3-256-Password":
            $rand_salt = bin2hex(random_bytes(16));
            $salted_hash = hash("sha3-256", "{$value}{$rand_salt}");
            $b64coded = base64_encode("{$salted_hash}{$rand_salt}");
            return "{ssha3-256}{$b64coded}";
        case "SSHA3-384-Password":
            $rand_salt = bin2hex(random_bytes(16));
            $salted_hash = hash("sha3-384", "{$value}{$rand_salt}");
            $b64coded = base64_encode("{$salted_hash}{$rand_salt}");
            return "{ssha3-384}{$b64coded}";
        case "SSHA3-512-Password":
            $rand_salt = bin2hex(random_bytes(16));
            $salted_hash = hash("sha3-512", "{$value}{$rand_salt}");
            $b64coded = base64_encode("{$salted_hash}{$rand_salt}");
            return "{ssha3-512}{$b64coded}";

        default:
        // TODO
        //~ case "CHAP-Password":
        case "User-Password":
        case "Cleartext-Password":
            return $value;
    }
}

function has_password_like_attributes($dbSocket, $username)
{
    global $configValues, $logDebugSQL;

    $sql = sprintf(
        "SELECT COUNT(id) FROM %s WHERE op=':=' AND username='%s' AND attribute LIKE '%%-Password'",
        $configValues["CONFIG_DB_TBL_RADCHECK"],
        $dbSocket->escapeSimple($username),
    );
    $res = $dbSocket->query($sql);
    $logDebugSQL .= "$sql;\n";

    return intval($res->fetchrow()[0]) > 0;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (
        array_key_exists("csrf_token", $_POST) &&
        isset($_POST["csrf_token"]) &&
        dalo_check_csrf_token($_POST["csrf_token"])
    ) {
        include "../common/includes/db_open.php";

        if (!has_password_like_attributes($dbSocket, $login_user)) {
            // error
        } else {
            $current_password =
                isset($_POST["current_password"]) &&
                !empty(trim($_POST["current_password"]))
                    ? trim($_POST["current_password"])
                    : "";

            if (empty($current_password)) {
                // error
            } else {
                $new_password1 =
                    isset($_POST["new_password1"]) &&
                    !empty(trim($_POST["new_password1"]))
                        ? trim($_POST["new_password1"])
                        : "";
                $new_password2 =
                    isset($_POST["new_password2"]) &&
                    !empty(trim($_POST["new_password2"]))
                        ? trim($_POST["new_password2"])
                        : "";

                $error = false;
                if (empty($new_password1)) {
                    $error = true;
                    $failureMsg =
                        "The new password you provided is empty or invalid";
                } elseif (empty($new_password2)) {
                    $error = true;
                    $failureMsg =
                        "The new password (confirmation) you provided is empty or invalid";
                } elseif ($new_password1 !== $new_password2) {
                    $error = true;
                    $failureMsg =
                        "Password and password (confirmation) should match";
                }

                if (!$error) {
                    // get all password like attributes
                    $sql = sprintf(
                        "SELECT id, attribute, value FROM %s WHERE op=':=' AND username='%s' AND attribute LIKE '%%-Password'",
                        $configValues["CONFIG_DB_TBL_RADCHECK"],
                        $dbSocket->escapeSimple($login_user),
                    );
                    $res0 = $dbSocket->query($sql);
                    $logDebugSQL .= "$sql;\n";

                    $count = 0;
                    while ($row = $res0->fetchRow()) {
                        [$id, $password_type, $password_value] = $row;
                        $id = intval($id);

                        $current_hashed_password = hashPasswordAttribute(
                            $password_type,
                            $current_password,
                        );

                        if (
                            $current_hashed_password === false ||
                            $current_hashed_password !== $password_value
                        ) {
                            continue;
                        }
                        $new_hashed_password = hashPasswordAttribute(
                            $password_type,
                            $new_password1,
                        );
                        if (
                            strpos($password_type, "SHA2") === 0 ||
                            strpos($password_type, "SSHA") === 0 ||
                            strpos($password_type, "SHA3") === 0
                        ) {
                            $password_type = "Password-With-Header";
                        }

                        // we can procede
                        $sql = sprintf(
                            "UPDATE %s SET value='%s' WHERE id=%d",
                            $configValues["CONFIG_DB_TBL_RADCHECK"],
                            $dbSocket->escapeSimple($new_hashed_password),
                            $id,
                        );
                        $res1 = $dbSocket->query($sql);
                        $logDebugSQL .= "$sql;\n";

                        if (!DB::isError($res1)) {
                            // success
                            $count++;
                        }
                    }

                    if ($count > 0) {
                        // success
                        $successMsg = "$count auth password(s) have been changed";
                        $logAction = "User $login_user has changed their auth password(s) [num. $count]";
                    } else {
                        // failed
                        $failureMsg =
                            "Something went wrong while attempting to change your auth password(s)";
                        $logAction = "User $login_user failed to change their auth password(s)";
                    }
                }
            }
        }

        include "../common/includes/db_close.php";
    } else {
        // csrf
        $failureMsg = "CSRF token error";
        $logAction .= "$failureMsg on page: ";
    }
}

// print HTML prologue
$title = t("Intro", "prefpasswordedit.php");
$help = t("helpPage", "prefpasswordedit");

print_html_prologue($title, $langCode);

print_title_and_help($title, $help);

include_once "include/management/actionMessages.php";

$input_descriptors0 = [];

$input_descriptors0[] = [
    "name" => "current_password",
    "caption" => t("all", "CurrentPassword"),
    "type" => "password",
];

$input_descriptors0[] = [
    "name" => "new_password1",
    "caption" => t("all", "NewPassword"),
    "type" => "password",
];

$input_descriptors0[] = [
    "name" => "new_password2",
    "caption" => t("all", "VerifyPassword"),
    "type" => "password",
];

$input_descriptors0[] = [
    "name" => "csrf_token",
    "type" => "hidden",
    "value" => dalo_csrf_token(),
];

$input_descriptors0[] = [
    "type" => "button",
    "name" => "submit",
    "value" => "Change authentication password(s)",
    "onclick" => "return verifyPassword('new_password1', 'new_password2')",
];

// open form
open_form();

foreach ($input_descriptors0 as $input_descriptor) {
    print_form_component($input_descriptor);
}

close_form();

$inline_extra_js = <<<EOF
function verifyPassword(passwordStr1, passwordStr2) {

    objPasswordStr1 = document.getElementById(passwordStr1);
    objPassword1Val = objPasswordStr1.value;
    objPasswordStr2 = document.getElementById(passwordStr2);
    objPassword2Val = objPasswordStr2.value;

    if (objPassword1Val == objPassword2Val) {
        document.forms[0].submit();
    } else {
        alert("Passwords do not match, please re-type your new password and verify it");
        return false;
    }
}
EOF;

include "include/config/logging.php";

print_footer_and_html_epilogue($inline_extra_js);
