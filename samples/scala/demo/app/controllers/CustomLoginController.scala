package controllers

import javax.inject.Inject

import securesocial.controllers.BaseLoginPage
import play.api.mvc.{ Action, AnyContent, RequestHeader }
import play.api.Logger
import play.api.i18n.MessagesApi
import play.filters.csrf.CSRFAddToken
import securesocial.core.{ IdentityProvider, RuntimeEnvironment, SecureSocialConfig }
import service.DemoUser
import securesocial.core.services.RoutesService

import scala.concurrent.ExecutionContext

class CustomLoginController @Inject() (
    implicit override val env: RuntimeEnvironment,
    override implicit val messagesApi: MessagesApi,
    implicit val config: SecureSocialConfig,
    override implicit val executionContext: ExecutionContext,
    override implicit val cSRFAddToken: CSRFAddToken) extends BaseLoginPage {
  override def login: Action[AnyContent] = {
    Logger.debug("using CustomLoginController")
    super.login
  }
}

class CustomRoutesService @Inject() (override implicit val config: SecureSocialConfig) extends RoutesService.Default {
  override def loginPageUrl(implicit req: RequestHeader): String = controllers.routes.CustomLoginController.login().absoluteURL(config.sslEnabled)
}