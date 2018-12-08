package nl.brachio.ingapi.vertxshowcase

import io.vertx.core.DeploymentOptions
import io.vertx.core.json.JsonObject
import io.vertx.core.logging.LoggerFactory
import io.vertx.core.logging.SLF4JLogDelegateFactory
import io.vertx.reactivex.core.RxHelper
import io.vertx.reactivex.core.Vertx


/**
 * Showcase API in production ING openbanking.
 *
 * See https://developer.ing.com/api-marketplace/marketplace/5f5106c4-3413-4b3c-890a-bb4cfa165dba/reference
 */


fun main(args: Array<String>) {
  System.setProperty(LoggerFactory.LOGGER_DELEGATE_FACTORY_CLASS_NAME, SLF4JLogDelegateFactory::class.java.name)

  val config = JsonObject(object {}.javaClass.classLoader.getResource("config.json").readText(Charsets.UTF_8))

  val vertx = Vertx.vertx()
  RxHelper.deployVerticle(vertx, MainVerticle(), DeploymentOptions().setConfig(config))
    .subscribe({ _ ->
      vertx.close()
    }, { t ->
      t.printStackTrace()
      vertx.close()
    })
}



