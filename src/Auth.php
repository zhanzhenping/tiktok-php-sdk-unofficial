<?php

namespace Tiktok;

use Exception;
use GuzzleHttp\Client as GuzzleHttpClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;

/**
 * Created by PhpStorm
 * USER Zhanzhenping
 * Date 2022/12/10   16:15
 */
class Auth
{

	const DEFAULT_EXPIRY_SECONDS = 30;

	const AUTHORIZATION_CODE = "authorization_code";
	const REFRESH_TOKEN = "refresh_token";

	private $authorizationUri;
	private $exchangeTokenUri;
	private $redirectUri;
	private $state;
	private $scope;
	private $clientKey;
	private $clientSecret;
	private $code;
	private $accessToken;
	private $refreshToken;
	private $refreshTokenUri;

	public function __construct(array $config)
	{
		$opts = array_merge([
			'authorizationUri' => null,
			'redirectUri' => null,
			'exchangeTokenUri' => null,
			'state' => null,
			'clientKey' => null,
			'clientSecret' => null,
			'scope' => null,
			'refreshTokenUri' => null
		], $config);

		$this->setClientKey($opts['clientKey']);
		$this->setClientSecret($opts['clientSecret']);
		$this->setState($opts['state']);
		$this->setScope($opts['scope']);
		$this->setRedirectUri($opts['redirectUri']);
		$this->setAuthorizationUri($opts['authorizationUri']);
		$this->setExchangeTokenUri($opts['exchangeTokenUri']);
		$this->setRefreshTokenUri($opts['refreshTokenUri']);
	}

	public function setClientKey($clientKey)
	{
		$this->clientKey = $clientKey;
	}

	public function getClientKey()
	{
		return $this->clientKey;
	}

	public function setClientSecret($clientSecret)
	{
		$this->clientSecret = $clientSecret;
	}

	public function getClientSecret()
	{
		return $this->clientSecret;
	}

	public function setState($state)
	{
		$this->state = $state;
	}

	public function setScope($scope)
	{
		$this->scope = $scope;
	}

	public function setRedirectUri($url)
	{
		if (is_null($url)) {
			$this->redirectUri = null;
			return;
		}
		if (!$this->isAbsoluteUri($url)) {
			// "postmessage" is a reserved URI string in Google-land
			// @see https://developers.google.com/identity/sign-in/web/server-side-flow
			if ('postmessage' !== (string)$url) {
				throw new InvalidArgumentException(
					'Redirect URI must be absolute'
				);
			}
		}
		$this->redirectUri = (string)$url;
	}

	public function setExchangeTokenUri($exchangeTokenUri)
	{
		$this->exchangeTokenUri = $exchangeTokenUri;
	}

	public function setRefreshTokenUri($refreshTokenUri)
	{
		$this->refreshTokenUri = $refreshTokenUri;
	}

	public function getRefreshTokenUri()
	{
		return $this->refreshTokenUri;
	}

	public function getExchangeTokenUri()
	{
		return $this->exchangeTokenUri;
	}

	public function getRedirectUri()
	{
		return $this->redirectUri;
	}

	public function setAuthorizationUri($authorizationUri)
	{
		$this->authorizationUri = $this->coerceUri($authorizationUri);
	}

	public function getAuthorizationUri()
	{
		return $this->authorizationUri;
	}

	public function setCode($code)
	{
		$this->code = $code;
	}

	public function getCode()
	{
		return $this->code;
	}

	public function buildAuthorizationUri($config)
	{

		if (is_null($this->getAuthorizationUri())) {
			throw new InvalidArgumentException(
				'requires an authorizationUri to have been set'
			);
		}

		$params = array_merge([
			'response_type' => 'code',
			'client_key' => $this->clientKey,
			'redirect_uri' => $this->redirectUri,
			'state' => $this->state,
			'scope' => $this->getScope(),
		], $config);

		if (is_null($params['client_key'])) {
			throw new InvalidArgumentException(
				'missing the required client identifier'
			);
		}
		if (is_null($params['redirect_uri'])) {
			throw new InvalidArgumentException('missing the required redirect URI');
		}

		$authorizationUri = clone $this->authorizationUri;
		$existingParams = Query::parse($authorizationUri->getQuery());

		$result = $authorizationUri->withQuery(
			Query::build(array_merge($existingParams, $params))
		);

		if ($result->getScheme() != 'https') {
			throw new InvalidArgumentException(
				'Authorization endpoint must be protected by TLS'
			);
		}

		return $result;
	}

	/**
	 * @throws GuzzleException
	 * @throws Exception
	 */
	public function fetchToken(GuzzleHttpClient $httpHandler = null)
	{
		$credentials = $this->parseResponse($httpHandler->send($this->generateCredentialsRequestHandle()));
		return $credentials['data'];
	}

	public function getScope()
	{
		if (is_null($this->scope)) {
			return $this->scope;
		}

		return implode(' ', $this->scope);
	}

	public function setRefreshToken($refreshToken)
	{
		$this->refreshToken = $refreshToken;
	}

	public function getRefreshToken()
	{
		return $this->refreshToken;
	}

	public function setAccessToken($accessToken)
	{
		$this->accessToken = $accessToken;
	}

	public function getAccessToken()
	{
		return $this->accessToken;
	}

	protected function updateToken(array $config)
	{
		$opts = array_merge([
			'access_token' => null,
			'expires_in' => null,
			'log_id' => null,
			'open_id' => null,
			'refresh_expires_in' => null,
			'refresh_token' => null,
			'expires_at' => null,
			'scope' => null,
		], $config);

		$this->setAccessToken($opts['access_token']);
	}

	protected function parseResponse(ResponseInterface $resp)
	{
		$body = (string)$resp->getBody();
		if ($resp->hasHeader('Content-Type') &&
			$resp->getHeaderLine('Content-Type') == 'application/x-www-form-urlencoded'
		) {
			$res = [];
			parse_str($body, $res);

			return $res;
		}

		// Assume it's JSON; if it's not throw an exception
		if (null === $res = json_decode($body, true)) {
			throw new \Exception('Invalid JSON response');
		}

		return $res;
	}

	protected function getGrantType()
	{
		if (!is_null($this->code)) {
			return self::AUTHORIZATION_CODE;
		}

		if (!is_null($this->refreshToken)) {
			return self::REFRESH_TOKEN;
		}

		return null;
	}

	protected function getRequestUri()
	{
		if (!is_null($this->code)) {
			return $this->getExchangeTokenUri();
		}

		if (!is_null($this->refreshToken)) {
			return $this->getRefreshTokenUri();
		}

		return null;
	}

	/**
	 * @throws \Exception
	 */
	protected function generateCredentialsRequestHandle()
	{
		$grantType = $this->getGrantType();
		$uri = $this->getRequestUri();

		if (is_null($uri)) throw new Exception("");

		$params = ['grant_type' => $grantType];
		switch ($grantType) {
			case self::AUTHORIZATION_CODE:
				$params['code'] = $this->getCode();
				$this->addClientCredentialsParams($params);
				break;
			case self::REFRESH_TOKEN:
				$params['refresh_token'] = $this->getRefreshToken();
				$this->addClientCredentialsParams($params, false);
				break;
			default:
				throw new \Exception("Missing authorization code");
		}


		$headers = [
			'Cache-Control' => 'no-store',
			'Content-Type' => 'application/x-www-form-urlencoded',
		];

		return new Request(
			'POST',
			$uri,
			$headers,
			Query::build($params)
		);
	}

	protected function addClientCredentialsParams(&$params, $clientSecretParams = true)
	{
		$clientKey = $this->getClientKey();
		$clientSecret = $this->getClientSecret();

		if ($clientKey) {
			$params['client_key'] = $clientKey;

			if ($clientSecretParams) {
				$params['client_secret'] = $clientSecret;
			}

		}

		return $params;
	}

	private function coerceUri($uri)
	{
		if (is_null($uri)) {
			return null;
		}

		return Utils::uriFor($uri);
	}

	/**
	 * Determines if the URI is absolute based on its scheme and host or path
	 * (RFC 3986).
	 *
	 * @param string $uri
	 * @return bool
	 */
	private function isAbsoluteUri($uri)
	{
		$uri = $this->coerceUri($uri);

		return $uri->getScheme() && ($uri->getHost() || $uri->getPath());
	}
}