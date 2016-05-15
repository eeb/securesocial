package securesocial.core

import akka.actor.ActorSystem
import play.api.cache.CacheApi
import play.api.i18n.MessagesApi
import play.api.libs.concurrent.{ Execution => PlayExecution }
import play.api.libs.mailer.MailerClient
import play.api.libs.ws.WSClient
import securesocial.controllers.{ MailTemplates, ViewTemplates }
import securesocial.core.authenticator._
import securesocial.core.providers._
import securesocial.core.providers.utils.{ Mailer, PasswordHasher, PasswordValidator }
import securesocial.core.services._

import scala.collection.immutable.ListMap
import scala.concurrent.ExecutionContext

/**
 * A runtime environment where the services needed are available
 */
trait RuntimeEnvironment {

  type U

  def routes: RoutesService

  def viewTemplates: ViewTemplates

  def mailTemplates: MailTemplates

  def mailer: Mailer

  def currentHasher: PasswordHasher

  def passwordHashers: Map[String, PasswordHasher]

  def passwordValidator: PasswordValidator

  def httpService: HttpService

  def cacheService: CacheService

  def avatarService: Option[AvatarService]

  def providers: Map[String, IdentityProvider]

  def idGenerator: IdGenerator

  def authenticatorService: AuthenticatorService[U]

  def eventListeners: Seq[EventListener]

  def userService: UserService[U]

  implicit val executionContext: ExecutionContext
  implicit val config: SecureSocialConfig
  implicit val cache: CacheApi
  implicit val messagesApi: MessagesApi
  implicit val ws: WSClient
  implicit val actorSystem: ActorSystem
  implicit val mailerClient: MailerClient
}

object RuntimeEnvironment {

  /**
   * A default runtime environment.  All built in services are included.
   * You can start your app with with by only adding a userService to handle users.
   */
  abstract class Default extends RuntimeEnvironment {

    override lazy val routes: RoutesService = new RoutesService.Default()
    implicit val runtimeEnv = this

    override lazy val viewTemplates: ViewTemplates = new ViewTemplates.Default()
    override lazy val mailTemplates: MailTemplates = new MailTemplates.Default()
    override lazy val mailer: Mailer = new Mailer.Default(mailTemplates)

    override lazy val currentHasher: PasswordHasher = new PasswordHasher.Default()
    override lazy val passwordHashers: Map[String, PasswordHasher] = Map(currentHasher.id -> currentHasher)
    override lazy val passwordValidator: PasswordValidator = new PasswordValidator.Default()

    override lazy val httpService: HttpService = new HttpService.Default
    override lazy val cacheService: CacheService = new CacheService.Default
    override lazy val avatarService: Option[AvatarService] = Some(new AvatarService.Default(httpService))
    override lazy val idGenerator: IdGenerator = new IdGenerator.Default()

    override lazy val authenticatorService = new AuthenticatorService(
      new CookieAuthenticatorBuilder[U](new AuthenticatorStore.Default(cacheService), idGenerator),
      new HttpHeaderAuthenticatorBuilder[U](new AuthenticatorStore.Default(cacheService), idGenerator)
    )

    override lazy val eventListeners: Seq[EventListener] = Seq()

    protected def include(p: IdentityProvider) = p.id -> p

    protected def oauth1ClientFor(provider: String) = new OAuth1Client.Default(config.forProvider(provider), httpService)

    protected def oauth2ClientFor(provider: String) = new OAuth2Client.Default(httpService, config.forOAuth2Provider(provider))

    override lazy val providers = ListMap(
      // oauth 2 client providers
      include(new FacebookProvider(routes, cacheService, oauth2ClientFor(FacebookProvider.Facebook), config)),
      include(new FoursquareProvider(routes, cacheService, oauth2ClientFor(FoursquareProvider.Foursquare), config)),
      include(new GitHubProvider(routes, cacheService, oauth2ClientFor(GitHubProvider.GitHub), config)),
      include(new GoogleProvider(routes, cacheService, oauth2ClientFor(GoogleProvider.Google), config)),
      include(new InstagramProvider(routes, cacheService, oauth2ClientFor(InstagramProvider.Instagram), config)),
      //include(new ConcurProvider(routes, cacheService, oauth2ClientFor(ConcurProvider.Concur), config)),
      include(new SoundcloudProvider(routes, cacheService, oauth2ClientFor(SoundcloudProvider.Soundcloud), config)),
      //include(new LinkedInOAuth2Provider(routes, cacheService,oauth2ClientFor(LinkedInOAuth2Provider.LinkedIn))),
      include(new VkProvider(routes, cacheService, oauth2ClientFor(VkProvider.Vk), config)),
      include(new DropboxProvider(routes, cacheService, oauth2ClientFor(DropboxProvider.Dropbox), config)),
      include(new WeiboProvider(routes, cacheService, oauth2ClientFor(WeiboProvider.Weibo), config)),
      include(new ConcurProvider(routes, cacheService, oauth2ClientFor(ConcurProvider.Concur), config)),
      include(new SpotifyProvider(routes, cacheService, oauth2ClientFor(SpotifyProvider.Spotify), config)),
      include(new SlackProvider(routes, cacheService, oauth2ClientFor(SlackProvider.Slack), config)),
      // oauth 1 client providers
      include(new LinkedInProvider(routes, cacheService, oauth1ClientFor(LinkedInProvider.LinkedIn))),
      include(new TwitterProvider(routes, cacheService, oauth1ClientFor(TwitterProvider.Twitter))),
      include(new XingProvider(routes, cacheService, oauth1ClientFor(XingProvider.Xing))),
      // username password
      include(new UsernamePasswordProvider[U](userService, avatarService, viewTemplates, passwordHashers))
    )
  }

}
