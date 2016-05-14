/**
 * Copyright 2012-2014 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
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
package securesocial.controllers

import javax.inject.Inject

import play.api.Environment
import play.api.data.Forms._
import play.api.data._
import play.api.i18n._
import play.api.mvc.Action
import play.filters.csrf.{ CSRFCheck, _ }
import securesocial.core._
import securesocial.core.providers.utils._
import securesocial.core.services.SaveMode

import scala.concurrent.{ Await, ExecutionContext, Future }

/**
 * A default Registration controller that uses the BasicProfile as the user type
 *
 * @param env the environment
 */
class Registration @Inject() (
  override implicit val env: RuntimeEnvironment,
  val messagesApi: MessagesApi,
  override implicit val config: SecureSocialConfig,
  implicit val environment: Environment,
  override val executionContext: ExecutionContext) extends BaseRegistration

/**
 * A trait that provides the means to handle user registration
 *
 */
trait BaseRegistration extends MailTokenBasedOperations {

  import securesocial.controllers.BaseRegistration._

  private val logger = play.api.Logger("securesocial.controllers.Registration")
  implicit val config: SecureSocialConfig

  val providerId = config.UsernamePassword

  val UserName = "userName"
  val FirstName = "firstName"
  val LastName = "lastName"

  def getFormWithUsername(messages: Messages) = Form[RegistrationInfo](
    mapping(
      UserName -> nonEmptyText.verifying(messages(UserNameAlreadyTaken), userName => {
        // todo: see if there's a way to avoid waiting here :-\
        import scala.concurrent.duration._
        Await.result(env.userService.find(providerId, userName), 20.seconds).isEmpty
      }),
      FirstName -> nonEmptyText,
      LastName -> nonEmptyText,
      Password ->
        tuple(
          Password1 -> nonEmptyText.verifying(PasswordValidator.constraint),
          Password2 -> nonEmptyText
        ).verifying(messages(PasswordsDoNotMatch), passwords => passwords._1 == passwords._2)
    ) // binding
    ((userName, firstName, lastName, password) => RegistrationInfo(Some(userName), firstName, lastName, password._1)) // unbinding
    (info => Some((info.userName.getOrElse(""), info.firstName, info.lastName, ("", ""))))
  )

  def getFormWithoutUsername(messages: Messages) = Form[RegistrationInfo](
    mapping(
      FirstName -> nonEmptyText,
      LastName -> nonEmptyText,
      Password ->
        tuple(
          Password1 -> nonEmptyText.verifying(PasswordValidator.constraint),
          Password2 -> nonEmptyText
        ).verifying(messages(PasswordsDoNotMatch), passwords => passwords._1 == passwords._2)
    ) // binding
    ((firstName, lastName, password) => RegistrationInfo(None, firstName, lastName, password._1)) // unbinding
    (info => Some((info.firstName, info.lastName, ("", ""))))
  )

  def getForm(messages: Messages) = if (config.withUserNameSupport) getFormWithUsername(messages) else getFormWithoutUsername(messages)

  @Inject
  implicit var CSRFAddToken: CSRFAddToken = null

  /**
   * Starts the sign up process
   */
  def startSignUp = CSRFAddToken {
    Action {
      implicit request =>
        if (enableRefererAsOriginalUrl) {
          SecureSocial.withRefererAsOriginalUrl(Ok(env.viewTemplates.getStartSignUpPage(startForm)))
        } else {
          Ok(env.viewTemplates.getStartSignUpPage(startForm))
        }
    }
  }

  @Inject
  implicit var CSRFCheck: CSRFCheck = null

  def handleStartSignUp = CSRFCheck {
    Action.async {
      implicit request =>
        startForm.bindFromRequest.fold(
          errors => {
            Future.successful(BadRequest(env.viewTemplates.getStartSignUpPage(errors)))
          },
          e => {
            val email = e.toLowerCase
            // check if there is already an account for this email address
            env.userService.findByEmailAndProvider(email, config.UsernamePassword).map {
              maybeUser =>
                maybeUser match {
                  case Some(user) =>
                    // user signed up already, send an email offering to login/recover password
                    env.mailer.sendAlreadyRegisteredEmail(user)
                  case None =>
                    createToken(email, isSignUp = true).flatMap { token =>
                      env.mailer.sendSignUpEmail(email, token.uuid)
                      env.userService.saveToken(token)
                    }
                }
                handleStartResult().flashing(Success -> messagesApi.preferred(request)(ThankYouCheckEmail), Email -> email)
            }
          }
        )
    }
  }

  /**
   * Renders the sign up page
   *
   * @return
   */
  def signUp(token: String) = CSRFAddToken {
    Action.async {
      implicit request =>
        logger.debug("[securesocial] trying sign up with token %s".format(token))
        executeForToken(token, true, {
          _ =>
            Future.successful(Ok(env.viewTemplates.getSignUpPage(getForm(messagesApi.preferred(request)), token)))
        })
    }
  }

  /**
   * Handles posts from the sign up page
   */
  def handleSignUp(token: String) = CSRFCheck {
    Action.async {
      implicit request =>

        executeForToken(token, true, {
          t =>
            getForm(messagesApi.preferred(request)).bindFromRequest.fold(
              errors => {
                logger.debug("[securesocial] errors " + errors)
                Future.successful(BadRequest(env.viewTemplates.getSignUpPage(errors, t.uuid)))
              },
              info => {
                val id = if (config.withUserNameSupport) info.userName.get else t.email
                val newUser = BasicProfile(
                  providerId,
                  id,
                  Some(info.firstName),
                  Some(info.lastName),
                  Some("%s %s".format(info.firstName, info.lastName)),
                  Some(t.email),
                  None,
                  AuthenticationMethod.UserPassword,
                  passwordInfo = Some(env.currentHasher.hash(info.password))
                )

                val withAvatar = env.avatarService.map {
                  _.urlFor(t.email).map { url =>
                    if (url != newUser.avatarUrl) newUser.copy(avatarUrl = url) else newUser
                  }
                }.getOrElse(Future.successful(newUser))

                import securesocial.core.utils._
                val result = for (
                  toSave <- withAvatar;
                  saved <- env.userService.save(toSave, SaveMode.SignUp);
                  deleted <- env.userService.deleteToken(t.uuid)
                ) yield {
                  if (config.sendWelcomeEmail)
                    env.mailer.sendWelcomeEmail(newUser)
                  val eventSession = Events.fire(new SignUpEvent(saved)).getOrElse(request.session)
                  if (config.signupSkipLogin) {
                    env.authenticatorService.find(config.Id).map {
                      _.fromUser(saved).flatMap { authenticator =>
                        confirmationResult()
                          .flashing(Success -> messagesApi.preferred(request)(SignUpDone))
                          .withSession(eventSession - SecureSocial.OriginalUrlKey - config.SessionId)
                          .startingAuthenticator(authenticator)
                      }
                    } getOrElse {
                      logger.error("[securesocial] There isn't CookieAuthenticator registered in the RuntimeEnvironment")
                      Future.successful(confirmationResult().flashing(Error -> messagesApi.preferred(request)("There was an error signing you up")))
                    }
                  } else {
                    Future.successful(confirmationResult().flashing(Success -> messagesApi.preferred(request)(SignUpDone)).withSession(eventSession))
                  }
                }
                result.flatMap(f => f)
              })
        })
    }
  }
}

object BaseRegistration {
  val UserNameAlreadyTaken = "securesocial.signup.userNameAlreadyTaken"
  val ThankYouCheckEmail = "securesocial.signup.thankYouCheckEmail"
  val InvalidLink = "securesocial.signup.invalidLink"
  val SignUpDone = "securesocial.signup.signUpDone"
  val Password = "password"
  val Password1 = "password1"
  val Password2 = "password2"

  val PasswordsDoNotMatch = "securesocial.signup.passwordsDoNotMatch"
}

/**
 * The data collected during the registration process
 *
 * @param userName  the username
 * @param firstName the first name
 * @param lastName  the last name
 * @param password  the password
 */
case class RegistrationInfo(userName: Option[String], firstName: String, lastName: String, password: String)
