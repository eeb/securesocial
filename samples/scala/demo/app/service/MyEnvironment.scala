package service

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

import akka.actor.ActorSystem
import com.google.inject.Inject
import controllers.CustomRoutesService
import play.api.cache.CacheApi
import play.api.i18n.MessagesApi
import play.api.libs.mailer.MailerClient
import play.api.libs.ws.WSClient
import securesocial.core.{ RuntimeEnvironment, SecureSocialConfig }

import scala.concurrent.ExecutionContext

class MyEnvironment @Inject() (
    implicit override val executionContext: ExecutionContext,
    val messagesApi: MessagesApi,
    override val config: SecureSocialConfig,
    override val cache: CacheApi,
    override val ws: WSClient,
    override val actorSystem: ActorSystem,
    override val mailerClient: MailerClient) extends RuntimeEnvironment.Default {

  override type U = DemoUser
  override lazy val routes = new CustomRoutesService()
  override lazy val userService: InMemoryUserService = new InMemoryUserService()
  override lazy val eventListeners = List(new MyEventListener())

}

/*
class MyBasicEnvironment @Inject() (val env: MyEnvironment[U]) extends RuntimeEnvironment.Default[U] {
  override lazy val userService: InMemoryUserService = env.userService
}*/
