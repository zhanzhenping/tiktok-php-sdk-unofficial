<?php

namespace TiktokUnofficial;

use GuzzleHttp\Client as GuzzleHttpClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use InvalidArgumentException;
use LogicException;
use Tiktok\Token\RevokeToken;

/**
 * Created by PhpStorm
 * USER Zhanzhenping
 * Date 2022/12/10   15:23
 */
class Client
{
	const OAUTH_URI = "https://www.tiktok.com/auth/authorize/";
	const TOKEN_URL = "https://open-api.tiktok.com/oauth/access_token/";
	const REFRESH_TOKEN_URL = "https://open-api.tiktok.com/oauth/refresh_token/";
	const USER_INFO_URL_V2 = "https://open.tiktokapis.com/v2/user/info/";
	const REVOKE_URL = "https://open-api.tiktok.com/oauth/revoke/";

	private $auth;

	private $http;

	private $credentials;

	/**
	 * @var array $config
	 */
	private $config;

	/** @var array $scopes */
	private $requestedScopes = [];

	public function __construct(array $config = [])
	{

		$this->config = array_merge([
			'client_id' => '',
			'client_secret' => '',
			'scopes' => null,
			'redirect_uri' => null,
			'state' => null,
		], $config);

		if (!is_null($this->config['scopes'])) {
			$this->setScopes($this->config['scopes']);
			unset($this->config['scopes']);
		}
	}

	/**
	 * @param $clientKey
	 * @description
	 * @date 2022/12/10
	 * @author zhanzhenping
	 */
	public function setClientKey($clientKey)
	{
		$this->config['client_key'] = $clientKey;
	}

	public function getClientKey()
	{
		return $this->config['client_key'];
	}

	/**
	 * @param $state
	 * @description
	 * @date 2022/12/10
	 * @author zhanzhenping
	 */
	public function setState($state)
	{
		$this->config['state'] = $state;
	}

	public function getState()
	{
		return $this->config['state'];
	}

	/**
	 * @param $clientSecret
	 * @description
	 * @date 2022/12/10
	 * @author zhanzhenping
	 */
	public function setClientSecret($clientSecret)
	{
		$this->config['client_secret'] = $clientSecret;
	}

	public function getClientSecret()
	{
		return $this->config['client_secret'];
	}

	/**
	 * @param $redirectUri
	 * @description
	 * @date 2022/12/10
	 * @author zhanzhenping
	 */
	public function setRedirectUri($redirectUri)
	{
		$this->config['redirect_uri'] = $redirectUri;
	}

	public function getRedirectUri()
	{
		return $this->config['redirect_uri'];
	}

	public function createAuthUrl()
	{
		$scopes = $this->prepareScopes();

		if (is_array($scopes)) {
			$scopes = implode(',', $scopes);
		}

		$params = array_filter([
			'response_type' => 'code',
			'scope' => $scopes,
			'state' => $this->config['state'],
		]);

		$auth = $this->getOAuthService();

		return (string)$auth->buildAuthorizationUri($params);
	}

	/**
	 * @throws GuzzleException
	 */
	public function fetchAccessTokenWithAuthCode($code)
	{
		if (strlen($code) == 0) {
			throw new InvalidArgumentException("Invalid code");
		}

		$auth = $this->getOAuthService();
		$auth->setCode($code);

		$credentials = $auth->fetchToken($this->getHttpClient());

		if ($credentials && isset($credentials['access_token'])) {
			$credentials['expires_at'] = time();
			$this->setCredentials($credentials);
		}

		return $credentials;
	}

	public function setCredentials($credentials)
	{
		if ($credentials == null) {
			throw new InvalidArgumentException('invalid json token');
		}
		if (!isset($credentials['access_token'])) {
			throw new InvalidArgumentException("Invalid token format");
		}
		$this->credentials = $credentials;
	}

	public function getCredentials()
	{
		return $this->credentials;
	}

	/**
	 * @return bool
	 * @description
	 * @date 2022/12/13
	 * @author zhanzhenping
	 */
	public function verifyAccessTokenExpired()
	{
		if (!$this->credentials) return true;

		if (!isset($this->credentials['expires_in'])) {
			return true;
		}

		$expiresAt = 0;
		if (isset($this->credentials['expires_at'])) {
			$expiresAt = $this->credentials['expires_at'];
		}

		return ($expiresAt + ($this->credentials['expires_in'] - Auth::DEFAULT_EXPIRY_SECONDS)) < time();
	}

	public function verifyRefreshTokenExpired()
	{
		if (!$this->credentials) return true;

		if (!isset($this->credentials['refresh_expires_in'])) {
			return true;
		}

		$expiresAt = 0;
		if (isset($this->credentials['expires_at'])) {
			$expiresAt = $this->credentials['expires_at'];
		}

		return ($expiresAt + ($this->credentials['refresh_expires_in'] - Auth::DEFAULT_EXPIRY_SECONDS)) < time();
	}

	/**
	 * @throws GuzzleException
	 */
	public function refreshToken($refreshToken = null)
	{
		if (null === $refreshToken) {
			if (!isset($this->credentials['refresh_token'])) {
				throw new LogicException(
					'refresh token must be passed in or set as part of setAccessToken'
				);
			}
			$refreshToken = $this->credentials['refresh_token'];
		}

		$auth = $this->getOAuthService();
		$auth->setRefreshToken($refreshToken);
		$credentials = $auth->fetchToken($this->getHttpClient());

		if ($credentials && isset($credentials['access_token'])) {
			$credentials['expires_at'] = time();
			$this->setCredentials($credentials);
		}

		return $credentials;
	}

	/**
	 * @throws GuzzleException
	 */
	public function revokeToken($token = null)
	{
		$tokenRevoker = new RevokeToken($this->getHttpClient());

		return $tokenRevoker->revokeAccess($token ?: $this->getCredentials());
	}

	/**
	 * @param $scope_or_scopes
	 * @description
	 * @date 2022/12/10
	 * @author zhanzhenping
	 */
	public function setScopes($scope_or_scopes)
	{
		$this->requestedScopes = [];
		$this->addScope($scope_or_scopes);
	}

	/**
	 * @param $scope_or_scopes
	 * @description
	 * @date 2022/12/10
	 * @author zhanzhenping
	 */
	public function addScope($scope_or_scopes)
	{
		if (is_string($scope_or_scopes) && !in_array($scope_or_scopes, $this->requestedScopes)) {
			$this->requestedScopes[] = $scope_or_scopes;
		} elseif (is_array($scope_or_scopes)) {
			foreach ($scope_or_scopes as $scope) {
				$this->addScope($scope);
			}
		}
	}

	private function getOAuthService()
	{
		if (!$this->auth) {
			$this->auth = new Auth([
				'clientKey'          => $this->getClientKey(),
				'clientSecret'      => $this->getClientSecret(),
				'authorizationUri'   => self::OAUTH_URI,
				'exchangeTokenUri' => self::TOKEN_URL,
				'refreshTokenUri' => self::REFRESH_TOKEN_URL,
				'redirectUri'       => $this->getRedirectUri(),
			]);
		}

		return $this->auth;
	}

	private function prepareScopes()
	{
		if (empty($this->requestedScopes)) {
			return null;
		}

		return implode(',', $this->requestedScopes);
	}

	/**
	 * @return ClientInterface
	 */
	public function getHttpClient()
	{
		if (null === $this->http) {
			$this->http = $this->createDefaultHttpClient();
		}

		return $this->http;
	}

	private function createDefaultHttpClient()
	{
		return new GuzzleHttpClient();
	}
}