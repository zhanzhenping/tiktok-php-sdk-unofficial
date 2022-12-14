# tiktok-php-sdk-unofficial
PHP login kit implemented according to tiktok document

<dl>
  <dt>Reference Docs</dt><dd><a href="https://developers.tiktok.com/doc/login-kit-overview/">https://developers.tiktok.com/doc/login-kit-overview/</a></dd>
  <dt>Login Kit</dt><dd>This is an unofficial SDK for the official Login Kit APIs.</dd>
</dl>

<dl>
  <dt>Features</dt>
    <dd>Current features include:</dd>

* Generate TikTok Authorization
* Obtain tiktok V2 user information
* Get access token
* Refresh expired Token
</dl>

<dl>
  <dt>Currently under improvement</dt>
    <dd>Video Kit</dd>
</dl>

### Installation

```sh
composer require stallzhan/tiktok-php-sdk-unofficial
```

### Basic Example

```php
// include your composer dependencies
require_once 'vendor/autoload.php';

try {
    $client = new \Tiktok\Client();
    $client->setClientKey("xxx");
    $client->setClientSecret("xxx");
    $client->setScopes([
        "user.info.basic",
        "video.upload"
    ]);
    $client->setState("xxx");
    $client->setRedirectUri("xxx");
    $authUrl = $client->createAuthUrl();
    header("Location: $authUrl");
    
    if ($_GET['code']) {
        $data = $client->fetchAccessTokenWithAuthCode($_GET['code']);
        $client->setCredentials($data);
    }
} catch (Exception $e) {
    var_dump($e->getMessage());
}

```

### Apis

#### Installation

Set credentials
```php
$client->setCredentials($data);
```

Obtain tiktok V2 user information
```php
$server = new \Tiktok\Service($client);
$userinfo = $server->userinfo_v2->get();
```

Refresh expired Token
```php
$data = $client->refreshToken();
```