import com.google.inject.{ AbstractModule, Inject, Scopes, TypeLiteral }
import net.codingwell.scalaguice.ScalaModule
import play.api.{ Configuration, Environment }
import play.api.inject.Module
import securesocial.core.{ BasicProfile, RuntimeEnvironment, SecureSocialConfig }
import service.{ DemoUser, MyEnvironment }

class DemoModule extends Module {

  def bindings(environment: Environment, configuration: Configuration) = {
    val config: SecureSocialConfig = new SecureSocialConfig(configuration, environment)

    Seq(
      bind(classOf[SecureSocialConfig]).to(config),
      bind(classOf[RuntimeEnvironment]).to(classOf[MyEnvironment])
    )
  }

}
