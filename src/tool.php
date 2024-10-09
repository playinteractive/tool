<?php
/**
 * @author    Salvador Baqués <salva@email5.com>
 * @link      https://stage.work
 * @copyright 2017 Stage Framework
 * @package   https://github.com/playinteractive
 */

/*
╔══════════════════════════════════════════════════════════════════════
║  STAGE ~ TOOLS ≡ tool.php
╠══════════════════════════════════════════════════════════════════════
║
*/

namespace Stage;

use SimpleXMLElement;

class Tool
{
    # ASSET

    private static $template;

    public static function template($template)
    {
        self::$template = $template;
    }

    public static function asset($name = FALSE, $base = TRUE, $root = TRUE, $host = TRUE, $version = FALSE)
    {
        global $template;

        return is_file(realpath(join(DIRECTORY_SEPARATOR, [$root = $root === NULL || $root === TRUE || $root === FALSE ? $_SERVER['DOCUMENT_ROOT'] : $root, $base = $base === NULL ? FALSE : ($base === TRUE ? (self::$template ?? $_ENV['STORAGE']) : ($base === FALSE ? $_ENV['STORAGE'] : (is_array($base) ? trim(implode('/', $base), '/') : trim($base, '/')))), $name = $name === NULL ? FALSE : ($name === TRUE ? FALSE : (is_array($name) ? trim(implode('/', $name), '/') : trim($name, '/')))]))) ? Tool::url([$base, $name], $version ?: filemtime(realpath(join(DIRECTORY_SEPARATOR, [$root, $base, $name]))), $host = $host === NULL || $host === TRUE || $host === FALSE ? ($template['storage'] ?? TRUE) : (filter_var(parse_url($host, PHP_URL_SCHEME)) ? $host : TRUE)) : Tool::url([$base, $name], $version, $host);
    }

    # CLI

    public static function CLI()
    {
        return php_sapi_name() === 'cli' || defined('STDIN') || array_key_exists('SHELL', $_ENV) || (empty($_SERVER['REMOTE_ADDR']) && !isset($_SERVER['HTTP_USER_AGENT']) && !empty($_SERVER['argv'])) || !isset($_SERVER['REQUEST_METHOD']);
    }

    # HTTPS

    public static function https()
    {
        return ((!empty($_SERVER['REQUEST_SCHEME']) && strtolower($_SERVER['REQUEST_SCHEME']) === 'https') || (!empty($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) === 'on' || $_SERVER['HTTPS'] == 1)) || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') || (!empty($_SERVER['HTTP_FRONT_END_HTTPS']) && (strtolower($_SERVER['HTTP_FRONT_END_HTTPS']) === 'on' || $_SERVER['HTTP_FRONT_END_HTTPS'] == 1)));
    }

    # INPUT

    public static function input()
    {
        if (isset($_SERVER['CONTENT_TYPE'])) {

            if (stripos($_SERVER['CONTENT_TYPE'], 'application/json') !== FALSE) {

                return self::JsonInput();

            } elseif (stripos($_SERVER['CONTENT_TYPE'], 'application/x-www-form-urlencoded') !== FALSE || stripos($_SERVER['CONTENT_TYPE'], 'multipart/form-data') !== FALSE) {

                return self::FormData();
            }
        }

        return FALSE;
    }

    private static function FormData()
    {
        return filter_input_array(INPUT_POST, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    }

    private static function JsonInput()
    {
        $json = json_decode(file_get_contents('php://input'), TRUE);

        if (json_last_error() === JSON_ERROR_NONE) return filter_var_array($json, FILTER_SANITIZE_FULL_SPECIAL_CHARS);

        return FALSE;
    }

    # PATH

    public static function path($pathname = FALSE, $basepath = FALSE)
    {
        return realpath(join(DIRECTORY_SEPARATOR, [$basepath ?: $_SERVER['SRC'], is_array($pathname) ? join(DIRECTORY_SEPARATOR, $pathname) : $pathname]));
    }

    # PERFORMANCE

    public static function benchmark()
    {
        return print_r(array(['memory_final' => number_format(memory_get_usage()), 'memory_initial' => number_format(USAGE['memory']), 'memory_peak' => number_format(memory_get_peak_usage()), 'time' => number_format((microtime(TRUE) - USAGE['time']), 3)]));
    }

    # REDIRECT

    public static function redirect($address = FALSE, $code = 301)
    {
        exit(header('Location:' . (filter_var($address, FILTER_VALIDATE_URL) ? $address : (filter_var($decoded = base64_decode($address), FILTER_VALIDATE_URL) ? $decoded : self::url(NULL))), TRUE, in_array($code, [301, 302, 307, 308]) ? $code : 301));
    }

    # RESPONSE

    public static function response($data, $format = MIME['application/json'], $api = API['rest'], $code = FALSE)
    {
        $format = strtolower($format) !== MIME['application/xml'] ? MIME['application/json'] : MIME['application/xml'];

        if ($code) Tool::status($code);

        switch (strtolower($api)) {

            case API['graphql']:

                return self::formatGraphQLData($data, $format);

            case API['soap']:

                return self::formatSOAPData($data, $format);

            case API['rest']:

                default:

                    if ($format === MIME['application/xml']) {

                        if (!is_array($data)) $data = ['response' => $data];

                        $firstKey = key($data);

                        $xmlData = new SimpleXMLElement("<$firstKey/>");

                        return self::arrayToXml($data[$firstKey], $xmlData)->asXML();

                    } else {

                        return is_array($data) ? json_encode($data) : json_encode(['response' => $data]);
                    }
        }
    }

    private static function arrayToXml($data, &$xmlData)
    {
        if (!is_array($data)) {

            $xmlData[0] = htmlspecialchars($data);

            return $xmlData;
        }

        foreach ($data as $key => $value) {

            if (!is_numeric($key)) {

                $key = preg_replace('/[^a-z0-9_]/i', '_', $key);

            } else {

                $key = 'item' . $key;
            }

            if (is_array($value)) {

                $subnode = $xmlData->addChild($key);

                self::arrayToXml($value, $subnode);

            } else {

                $xmlData->addChild($key, htmlspecialchars($value));
            }
        }

    return $xmlData;
    }

    private static function formatGraphQLData($data, $format = MIME['application/json'])
    {
        $response = [];

        if (isset($data['errors'])) $response['errors'] = $data['errors'];

        if (isset($data['data'])) {

            $response['data'] = $data['data'];

        } else {

            $response['data'] = $data;
        }

        if (strtolower($format) === MIME['application/xml']) {

            $xmlData = new SimpleXMLElement('<graphql/>');

            self::arrayToXml($response, $xmlData);

            return $xmlData->asXML();
        }

    return json_encode($response);
    }

    private static function formatSOAPData($data, $format = MIME['application/xml'])
    {
        if (strtolower($format) === MIME['application/json']) {

            $response = ['SOAP-ENV:Envelope' => ['SOAP-ENV:Body' => $data]];

            return json_encode($response);
        }

        $xmlData = new SimpleXMLElement('<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"/>');

        $body = $xmlData->addChild('SOAP-ENV:Body');

        if (!is_array($data)) $data = ['response' => $data];

        self::arrayToXml($data, $body);

        return $xmlData->asXML();
    }

    # SANITIZE STRING

    public static function sanitize($string, $db = FALSE)
    {
        return $db ? $db->real_escape_string(trim(strip_tags($string))) : trim(strip_tags($string));
    }

    # SANITIZE URL

    public static function sanitizeURL($string, $lower = FALSE, $separator = '-')
    {
        return str_replace(' ', $separator, trim(preg_replace('/\s\s+/', ' ', str_replace(['"', '<', '>', '\\', '|', '{', '}', '^', '#', '$', '%', '&', '*', '=', '[', ']', '!', '?', ':', ';', '´', '`', '~', '(',')', "'"], '', $lower ? mb_strtolower($string) : $string))));
    }

    # SEND EMAIL

    public static function mail($to, $subject, $body)
    {
        global $transport;

        $mailer = new Swift_Mailer($transport);

        $message = (new Swift_Message($subject))->setFrom(['log@' . gethostname() => 'Error Logger'])->setTo([$to])->setBody($body);

        return $mailer->send($message);
    }

    # STATUS CODE
    
    public static function status($code)
    {
        $codes = [
            400 => '400 Bad Request',
            401 => '401 Unauthorized',
            403 => '403 Forbidden',
            404 => '404 Not Found',
            405 => '405 Method Not Allowed',
            410 => '410 Gone',
            429 => '429 Too Many Requests',
            500 => '500 Internal Server Error',
            503 => '503 Service Unavailable',
        ];

        if (isset($codes[$code])) {

            header($_SERVER['SERVER_PROTOCOL'] . ' ' . $codes[$code]);
            header('Status: ' . $codes[$code]);

            if (in_array($code, [429, 503])) header('Retry-After: 3600');
        
        } else {

            header($_SERVER['SERVER_PROTOCOL'] . ' ' . $codes[$code = 500]);
            header('Status: ' . $codes[500]);
        }

        header('X-Robots-Tag: noindex, nofollow, noarchive');

        return http_response_code($_SERVER['REDIRECT_STATUS'] = $code);
    }

    # UNSET

    public static function unset()
    {
        $vars = ['AUTH', 'CLIENT', 'CONSOLE', 'HOST', 'KERNEL', 'MIDDLEWARE', 'REST', 'ROUTE', 'DB_NAME', 'DB_PWD', 'DB_SALT', 'DB_USER', 'KEY_PVT', 'KEY_PWD', 'PRIVATE', 'READFILE', 'SMTP_PWD', 'SMTP_SERVER', 'SMTP_USER'];

        foreach ($vars as $var) {

        unset($_ENV[$var], $_SERVER[$var]);

        putenv($var);
        }
    }

    # URL

    public static function url($path = TRUE, $query = NULL, $host = TRUE, $fragment = NULL, $combine = ['query' => NULL, 'type' => 'merge'])
    {
        return trim(join('/', [$host === TRUE ? SCHEME . HOST : (is_null($host) || $host === FALSE ? FALSE : (filter_var($phost = parse_url($host, PHP_URL_SCHEME) ? rtrim($host, '/') : str_replace(PROTOCOL, 'http', SCHEME) . rtrim($host, '/'), FILTER_VALIDATE_URL) ? $phost : FALSE)), $path === TRUE ? PATH : (is_null($path) || $path === FALSE ? FALSE : (is_array($path) ? implode('/', array_filter(array_map(fn($v) => trim($v, '/'), array_values($path)))) : trim($path, '/')))]), '/') . (is_null($path) ? (is_null($host) ? (is_null($query) ? FALSE : (self::query(($query === TRUE ? QUERY : ($query === FALSE ? rawurldecode(http_build_query(array_filter(GET ?? [], fn($key) => !in_array($key, CALL), ARRAY_FILTER_USE_KEY))) : (is_null($query) ? FALSE : (is_array($query) ? http_build_query($query) : ltrim($query, '?'))))), $combine))) : (is_null($query) ? FALSE : '/?' . (self::query(($query === TRUE ? QUERY : ($query === FALSE ? rawurldecode(http_build_query(array_filter(GET ?? [], fn($key) => !in_array($key, CALL), ARRAY_FILTER_USE_KEY))) : (is_null($query) ? FALSE : (is_array($query) ? http_build_query($query) : ltrim($query, '?'))))), $combine)))) : (is_null($query) ? FALSE : ((($fquery = (self::query(($query === TRUE ? QUERY : ($query === FALSE ? rawurldecode(http_build_query(array_filter(GET ?? [], fn($key) => !in_array($key, CALL), ARRAY_FILTER_USE_KEY))) : (is_null($query) ? FALSE : (is_array($query) ? http_build_query($query) : ltrim($query, '?'))))), $combine))) ? '?' . $fquery : FALSE)))) . $fragment;
    }

    private static function query($query = FALSE, $combine)
    {
        if (is_array($combine) && isset($combine[1])) {

            $nquery = $combine[0];
            $type = $combine[1];
    
        } else if (is_string($combine) || is_array($combine)) {

            $nquery = $combine;
            $type = 'merge';

        } else {

            $nquery = $combine['query'] ?? NULL;
            $type = $combine['type'] ?? 'merge';
        }

        if (empty($query)) {

            if (is_bool($nquery)) {

                return FALSE;

            } elseif (is_string($nquery)) {

                return $nquery;

            } else {

                return http_build_query($nquery ?? []);
            }
        }

        if ($type === 'merge' && !is_null($nquery)) {

            parse_str($query, $cquery);

                if (is_string($nquery)) {

                    parse_str($nquery, $arrquery);

                } else {

                    $arrquery = $nquery;
                }

            return http_build_query(array_merge($cquery, $arrquery));

        } elseif ($type === 'append' && !is_null($nquery)) {

            if (is_bool($nquery)) {

                return $query;

            } elseif (is_string($nquery)) {

                return ($query ? $query . '&' : '') . ltrim($nquery, '?');

            } else {

                return ($query ? $query . '&' : '') . http_build_query($nquery);
            }

        } elseif ($type === 'remove' && !is_null($nquery)) {

            parse_str($query, $cquery);

                if (is_array($nquery)) {

                    foreach ($nquery as $key) unset($cquery[$key]);

                } elseif (is_string($nquery)) {

                    unset($cquery[$nquery]);
                }

            return http_build_query($cquery);
        }

        return $query;
    }

    # VALIDATE TEXT

    public static function validateText($text, $db = FALSE, $tag = FALSE, $textarea = FALSE, $decoration = TRUE)
    {
        $dom = new DOMDocument;

        @$dom->loadHTML(mb_convert_encoding($decoration ? (preg_replace('/\"([^<>]*?)\"(?=(?:[^>]*?(?:<|$)))/', '“\1”', str_replace(array('`', '´'), array('‘', '’'), $textarea ? $text : trim(preg_replace(array('@([\r\n])[\s]+@', '@&(nbsp|#160);@i', '/\s\s+/u'), ' ', $text))))) : ($textarea ? $text : trim(preg_replace(array('@([\r\n])[\s]+@', '@&(nbsp|#160);@i', '/\s\s+/u'), ' ', $text))), 'HTML-ENTITIES'), LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);

        foreach ($dom->getElementsByTagName('a') as $node) {

            if (!$node->getAttribute('title')) $node->setAttribute('title', $node->getAttribute('href'));

            if ($node->getAttribute('target') == '_blank') {

                $node->removeAttribute('target');
                $node->setAttribute('class', 'external');
            }

            if (stripos($node->getAttribute('href'), 'mailto:') === 0) {

                $node->removeAttribute('target');
                $node->removeAttribute('class');
            }

            if (!(substr($node->getAttribute('href'), 0, 2) == '[[' && substr($node->getAttribute('href'), -2) == ']]')) if (!parse_url($node->getAttribute('href'), PHP_URL_SCHEME)) $node->setAttribute('href', 'http://' . $node->getAttribute('href'));
        }

        return $db ? $db->real_escape_string(html_entity_decode(rawurldecode(trim(strip_tags($dom->saveXML(), $tag))))) : html_entity_decode(rawurldecode(trim(strip_tags($dom->saveXML(), $tag))));
    }
}