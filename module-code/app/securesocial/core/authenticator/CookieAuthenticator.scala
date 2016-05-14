/**
 * Copyright 2013-2014 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package securesocial.core.authenticator

import javax.inject.Inject

import org.joda.time.DateTime
import play.api.{ Application, Configuration }
import play.api.mvc.{ Cookie, DiscardingCookie, RequestHeader, Result }
import securesocial.core.{ IdentityProvider, SecureSocialConfig }

import scala.concurrent.Future

/**
 * A Cookie based authenticator. This authenticator puts an id an a cookie that is then used to track authenticated
 * users.  Since the cookie only has the id for this authenticator the rest of the data is stored using an
 * instance of the AuthenticatorStore.
 *
 * @param id            the authenticator id
 * @param user          the user this authenticator is associated with
 * @param expirationDate the expiration date
 * @param lastUsed      the last time the authenticator was used
 * @param creationDate  the authenticator creation time
 * @param store         the authenticator store where instances of this authenticator are persisted
 * @tparam U the user type (defined by the application using the module)
 * @see AuthenticatorStore
 * @see RuntimeEnvironment
 */
case class CookieAuthenticator[U](id: String, user: U, expirationDate: DateTime,
  lastUsed: DateTime,
  creationDate: DateTime,
  @transient store: AuthenticatorStore[CookieAuthenticator[U]])(implicit val config: SecureSocialConfig)
    extends StoreBackedAuthenticator[U, CookieAuthenticator[U]] {

  @transient
  override val idleTimeoutInMinutes = config.idleTimeout

  @transient
  override val absoluteTimeoutInSeconds = config.absoluteTimeoutInSeconds

  /**
   * Returns a copy of this authenticator with the given last used time
   *
   * @param time the new time
   * @return the modified authenticator
   */
  def withLastUsedTime(time: DateTime): CookieAuthenticator[U] = this.copy[U](lastUsed = time)

  /**
   * Returns a copy of this Authenticator with the given user
   *
   * @param user the new user
   * @return the modified authenticator
   */
  def withUser(user: U): CookieAuthenticator[U] = this.copy[U](user = user)

  /**
   * Ends an authenticator session.  This is invoked when the user logs out or if the
   * authenticator becomes invalid (maybe due to a timeout)
   *
   * @param result the result that is about to be sent to the client.
   * @return the result modified to signal the authenticator is no longer valid
   */
  override def discarding(result: Result): Future[Result] = {
    store.delete(id).map { _ =>
      result.discardingCookies(config.discardingCookie)
    }
  }

  /**
   * Starts an authenticated session by placing a cookie in the result
   *
   * @param result the result that is about to be sent to the client
   * @return the result with the authenticator cookie set
   */
  override def starting(result: Result): Future[Result] = {
    Future.successful {
      result.withCookies(
        Cookie(
          config.cookieName,
          id,
          if (config.makeTransient)
            config.Transient
          else Some(config.absoluteTimeoutInSeconds),
          config.cookiePath,
          config.cookieDomain,
          secure = config.cookieSecure,
          httpOnly = config.cookieHttpOnly
        )
      )
    }
  }

  /**
   * Removes the authenticator from the store and discards the cookie associated with it.
   *
   * @param javaContext the current invocation context
   */
  override def discarding(javaContext: play.mvc.Http.Context): Future[Unit] = {
    store.delete(id).map { _ =>
      javaContext.response().discardCookie(
        config.cookieName,
        config.cookiePath,
        config.cookieDomain.getOrElse(null),
        config.cookieSecure
      )
    }
  }

  override val cookieConfig: SecureSocialConfig = config
}

/**
 * An authenticator builder. It can create an Authenticator instance from an http request or from a user object
 *
 * @param store    the store where instances of the CookieAuthenticator class are persisted.
 * @param generator a session id generator
 * @tparam U the user object type
 */
class CookieAuthenticatorBuilder[U](store: AuthenticatorStore[CookieAuthenticator[U]], generator: IdGenerator)(implicit val config: SecureSocialConfig) extends AuthenticatorBuilder[U] {

  import store.executionContext

  val id = config.Id

  /**
   * Creates an instance of a CookieAuthenticator from the http request
   *
   * @param request the incoming request
   * @return an optional CookieAuthenticator instance.
   */
  override def fromRequest(request: RequestHeader): Future[Option[CookieAuthenticator[U]]] = {
    request.cookies.get(config.cookieName) match {
      case Some(cookie) => store.find(cookie.value).map { retrieved =>
        retrieved.map { _.copy(store = store) }
      }
      case None => Future.successful(None)
    }
  }

  /**
   * Creates an instance of a CookieAuthenticator from a user object.
   *
   * @param user the user
   * @return a CookieAuthenticator instance.
   */
  override def fromUser(user: U): Future[CookieAuthenticator[U]] = {
    generator.generate.flatMap {
      id =>
        val now = DateTime.now()
        val expirationDate = now.plusMinutes(config.absoluteTimeout)
        val authenticator = CookieAuthenticator(id, user, expirationDate, now, now, store)
        store.save(authenticator, config.absoluteTimeoutInSeconds)
    }
  }
}

