package com.zcashme.zns

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URI

/**
 * Low-level JSON-RPC 2.0 transport over HTTP.
 *
 * This is an internal helper; consumers should use [ZnsClient] instead.
 */
internal object Rpc {

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Execute a JSON-RPC 2.0 call and return the `result` field as a [JsonElement].
     *
     * @throws ZnsError on HTTP errors or JSON-RPC errors.
     */
    suspend fun call(
        url: String,
        method: String,
        params: JsonElement = JsonObject(emptyMap()),
        id: Int = 1,
    ): JsonElement = withContext(Dispatchers.IO) {
        val requestBody = JsonObject(
            mapOf(
                "jsonrpc" to JsonPrimitive("2.0"),
                "id" to JsonPrimitive(id),
                "method" to JsonPrimitive(method),
                "params" to params,
            )
        ).toString()

        val connection = URI(url).toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.doOutput = true
            connection.connectTimeout = 30_000
            connection.readTimeout = 30_000

            OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(requestBody)
                writer.flush()
            }

            val statusCode = connection.responseCode
            val responseBody = if (statusCode in 200..299) {
                connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            } else {
                val errorBody = connection.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
                throw ZnsError(ZnsErrorType.HTTP_ERROR, "HTTP $statusCode: $errorBody")
            }

            val responseJson = json.parseToJsonElement(responseBody).jsonObject

            val error = responseJson["error"]
            if (error != null && error !is kotlinx.serialization.json.JsonNull) {
                val errorObj = error.jsonObject
                val code = errorObj["code"]?.jsonPrimitive?.content?.toIntOrNull() ?: -32603
                val message = errorObj["message"]?.jsonPrimitive?.content ?: "Unknown error"
                throw ZnsError.fromCode(code, message)
            }

            responseJson["result"] ?: kotlinx.serialization.json.JsonNull
        } finally {
            connection.disconnect()
        }
    }
}
