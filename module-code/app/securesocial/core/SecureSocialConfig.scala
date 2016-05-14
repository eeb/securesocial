package securesocial.core

import play.api.data.Forms._
import play.api.data.Form
import play.api.libs.oauth.{ ConsumerKey, ServiceInfo }
import play.api.mvc.DiscardingCookie
import play.api.{ Configuration, Environment, Mode }
import securesocial.core.providers.utils.PasswordHasher

/**
 * User: Scott Hathaway
 * Date: 5/13/16
 */
class SecureSocialConfig(configuration: Configuration, environment: Environment) {

  private val logger = play.api.Logger("securesocial.core.SecureSocialConfig")

  val configObj = configuration

  val SessionId = "sid"
  // todo: do I want this here?
  val sslEnabled: Boolean = {
    val result = configuration.getBoolean("securesocial.ssl").getOrElse(false)
    if (!result && environment.mode == Mode.Prod) {
      logger.warn(
        "[securesocial] IMPORTANT: Play is running in production mode but you did not turn SSL on for SecureSocial." +
          "Not using SSL can make it really easy for an attacker to steal your users' credentials and/or the " +
          "authenticator cookie and gain access to the system."
      )
    }
    result
  }

  val cookieAuthId = "cookie"
  val httpAuthId = "http"

  /**
   * Reads a property from the application.conf
   *
   * @param property
   * @return
   */
  def loadProperty(providerId: String, property: String, optional: Boolean = false): Option[String] = {
    val key = s"securesocial.$providerId.$property"
    val result = configuration.getString(key)
    if (result.isEmpty && !optional) {
      logger.warn(s"[securesocial] Missing property: $key ")
    }
    result
  }

  def throwMissingPropertiesException(id: String) {
    val msg = s"[securesocial] Missing properties for provider '$id'. Verify your configuration file is properly set."
    logger.error(msg)
    throw new RuntimeException(msg)
  }

  def forProvider(id: String): ServiceInfo = {
    val result = for {
      requestTokenUrl <- loadProperty(id, OAuth1Provider.RequestTokenUrl)
      accessTokenUrl <- loadProperty(id, OAuth1Provider.AccessTokenUrl)
      authorizationUrl <- loadProperty(id, OAuth1Provider.AuthorizationUrl)
      consumerKey <- loadProperty(id, OAuth1Provider.ConsumerKey)
      consumerSecret <- loadProperty(id, OAuth1Provider.ConsumerSecret)
    } yield {
      ServiceInfo(requestTokenUrl, accessTokenUrl, authorizationUrl, ConsumerKey(consumerKey, consumerSecret))
    }

    if (result.isEmpty) {
      throwMissingPropertiesException(id)
    }
    result.get

  }

  val AuthorizationUrl = "authorizationUrl"
  val AccessTokenUrl = "accessTokenUrl"
  val AuthorizationUrlParams = "authorizationUrlParams"
  val AccessTokenUrlParams = "accessTokenUrlParams"
  val ClientId = "clientId"
  val ClientSecret = "clientSecret"
  val Scope = "scope"

  /**
   * Helper method to create an OAuth2Settings instance from the properties file.
   *
   * @param id the provider id
   * @return an OAuth2Settings instance
   */
  def forOAuth2Provider(id: String): OAuth2Settings = {

    val propertyKey = s"securesocial.$id."

    val result = for {
      authorizationUrl <- loadProperty(id, AuthorizationUrl)
      accessToken <- loadProperty(id, AccessTokenUrl)
      clientId <- loadProperty(id, ClientId)
      clientSecret <- loadProperty(id, ClientSecret)
    } yield {
      val scope = loadProperty(id, Scope, optional = true)

      val authorizationUrlParams: Map[String, String] =
        configuration.getObject(propertyKey + AuthorizationUrlParams).map { o =>
          o.unwrapped.asInstanceOf[Map[String, String]]
        }.getOrElse(Map())

      val accessTokenUrlParams: Map[String, String] = configuration.getObject(propertyKey + AccessTokenUrlParams).map { o =>
        o.unwrapped.asInstanceOf[Map[String, String]]
      }.getOrElse(Map())
      OAuth2Settings(authorizationUrl, accessToken, clientId, clientSecret, scope, authorizationUrlParams, accessTokenUrlParams)
    }
    if (result.isEmpty) {
      throwMissingPropertiesException(id)
    }
    result.get
  }

  // property keys
  val CookieNameKey = "securesocial.cookie.name"
  val CookiePathKey = "securesocial.cookie.path"
  val CookieDomainKey = "securesocial.cookie.domain"
  val CookieHttpOnlyKey = "securesocial.cookie.httpOnly"
  val ApplicationContext = "application.context"
  val IdleTimeoutKey = "securesocial.cookie.idleTimeoutInMinutes"
  val AbsoluteTimeoutKey = "securesocial.cookie.absoluteTimeoutInMinutes"
  val TransientKey = "securesocial.cookie.makeTransient"

  // default values
  val DefaultCookieName = "id"
  val DefaultCookiePath = "/"
  val DefaultCookieHttpOnly = true
  val Transient = None
  val DefaultIdleTimeout = 30
  val DefaultAbsoluteTimeout = 12 * 60

  lazy val cookieName = configuration.getString(CookieNameKey).getOrElse(DefaultCookieName)
  lazy val cookiePath = configuration.getString(CookiePathKey).getOrElse(
    configuration.getString(ApplicationContext).getOrElse(DefaultCookiePath)
  )
  lazy val cookieDomain = configuration.getString(CookieDomainKey)
  lazy val cookieSecure = sslEnabled
  lazy val cookieHttpOnly = configuration.getBoolean(CookieHttpOnlyKey).getOrElse(DefaultCookieHttpOnly)
  lazy val idleTimeout = configuration.getInt(IdleTimeoutKey).getOrElse(DefaultIdleTimeout)
  lazy val absoluteTimeout = configuration.getInt(AbsoluteTimeoutKey).getOrElse(DefaultAbsoluteTimeout)
  lazy val absoluteTimeoutInSeconds = absoluteTimeout * 60
  lazy val makeTransient = configuration.getBoolean(TransientKey).getOrElse(true)

  val HeaderNameKey = "securesocial.auth-header.name"

  // default values
  val DefaultHeaderName = "X-Auth-Token"

  lazy val headerName = configuration.getString(HeaderNameKey).getOrElse(DefaultHeaderName)

  val discardingCookie: DiscardingCookie = {
    DiscardingCookie(cookieName, cookiePath, cookieDomain, cookieSecure)
  }

  val DefaultSizeInBytes = 128
  val IdLengthKey = "securesocial.idLengthInBytes"
  val IdSizeInBytes = configuration.getInt(IdLengthKey).getOrElse(DefaultSizeInBytes)

  def valueFor(key: String, default: String) = {
    val value = configuration.getString(key).getOrElse(default)
    logger.debug(s"[securesocial] $key = $value")
    securesocial.controllers.routes.Assets.at(value)
  }

  def customCSSPath(CustomCssKey: String) = {
    val path = configuration.getString(CustomCssKey).map(securesocial.controllers.routes.Assets.at)
    logger.debug("[securesocial] custom css path = %s".format(path))
    path
  }

  val UsernamePassword = "userpass"
  private val Key = "securesocial.userpass.withUserNameSupport"
  private val SendWelcomeEmailKey = "securesocial.userpass.sendWelcomeEmail"
  private val Hasher = "securesocial.userpass.hasher"
  private val EnableTokenJob = "securesocial.userpass.enableTokenJob"
  private val SignupSkipLogin = "securesocial.userpass.signupSkipLogin"

  lazy val withUserNameSupport = configuration.getBoolean(Key).getOrElse(false)
  lazy val sendWelcomeEmail = configuration.getBoolean(SendWelcomeEmailKey).getOrElse(true)
  lazy val hasher = configuration.getString(Hasher).getOrElse(PasswordHasher.id)
  lazy val enableTokenJob = configuration.getBoolean(EnableTokenJob).getOrElse(true)
  lazy val signupSkipLogin = configuration.getBoolean(SignupSkipLogin).getOrElse(false)

  val loginForm = Form(
    tuple(
      "username" -> nonEmptyText,
      "password" -> nonEmptyText
    )
  )

  /**
   * The property that specifies the page the user is redirected to if there is no original URL saved in
   * the session.
   */
  val onLoginGoTo = "securesocial.onLoginGoTo"

  /**
   * The root path
   */
  val Root = "/"

  /**
   * The url where the user needs to be redirected after succesful authentication.
   *
   * @return
   */
  def landingUrl = configuration.getString(onLoginGoTo).getOrElse(
    configuration.getString(ApplicationContext).getOrElse(Root)
  )

}
